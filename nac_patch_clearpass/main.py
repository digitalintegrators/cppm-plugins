# Plugin modificado para usar PATCH con ClearPass desde Cloud Exchange con atributos dinámicos y control de severidad

import requests
from .plugin_base import PluginBase

class ClearPassNACPlugin(PluginBase):
    def __init__(self, config):
        super().__init__(config)
        self.clearpass_url = config.get("clearpass_host")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.token = self._get_token()
        self.attribute_mapping = config.get("attribute_mapping", {})
        self.severity_threshold = config.get("severity_threshold", "high").lower()

    def _get_token(self):
        url = f"{self.clearpass_url}/api/oauth"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        response = requests.post(url, data=data, verify=False)
        response.raise_for_status()
        return response.json()["access_token"]

    def update_endpoint_attributes(self, endpoint_id, attributes):
        url = f"{self.clearpass_url}/api/endpoint/{endpoint_id}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        payload = {"attributes": attributes}
        response = requests.patch(url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        return response.json()

    def run(self, alert):
        mac = alert.get("mac_address")
        if not mac:
            self.logger.warning("No MAC address provided in alert.")
            return

        # Validar severidad
        alert_severity = alert.get("severity", "low").lower()
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_order.get(alert_severity, 0) < severity_order.get(self.severity_threshold, 3):
            self.logger.info(f"Alert severity '{alert_severity}' below threshold '{self.severity_threshold}'. Skipping.")
            return

        endpoint_id = mac.replace(":", "").lower()

        # Construir atributos desde el mapping
        attributes = {}
        for field, value in self.attribute_mapping.items():
            if isinstance(value, str) and value.startswith("$"):
                # Extraer del alert dinámicamente
                key = value[1:]
                attributes[field] = alert.get(key, "")
            else:
                attributes[field] = value

        try:
            result = self.update_endpoint_attributes(endpoint_id, attributes)
            self.logger.info(f"Updated endpoint {endpoint_id}: {result}")
        except Exception as e:
            self.logger.error(f"Failed to update endpoint {endpoint_id}: {e}")
