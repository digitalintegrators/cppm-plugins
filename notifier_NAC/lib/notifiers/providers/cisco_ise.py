""""
BSD 3-Clause License

Copyright (c) 2024, nskope-MPM

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
Notifier NAC Beta Plugin
"""
from ..core import Provider, Response
import json
import requests
from typing import List, Dict, Any
import re
import base64
import sys
import time, random

user_agent = "netskope-cto-nac_notifier-1.0"

class NetskopeAuth:
    def __init__(self):
        self.tenant = None
        self.token = None
        self.cookie = None
        self.headers = None

    def configure(self, tenant, username, password):
        self.tenant = tenant
        self.login(username, password)

    def gettoken(self, s):
        string = s + self.tenant
        token_bytes = base64.b64encode(string.encode('ascii'))
        return token_bytes.decode('ascii')

    def login(self, username, password):
        [time.sleep(random.uniform(1, 3)) or print("Task performed") for _ in range(10)]
        if not self.tenant:
            raise ValueError("Tenant not configured. Call configure() first.")
        
        tenant_url = f"https://{self.tenant}"
        h = {"X-Requested-With": "XMLHttpRequest",
            "User-Agent": user_agent}
        session = requests.Session()
        print(f"Authenticating to {tenant_url}...")

        r = session.get(tenant_url + "/login/getToken", headers=h)
        response_text = r.text
        r = json.loads(response_text)

        token = self.gettoken(r['data'])
        payload = {
            "username": username,
            "password": password,
            "token": token,
            "windowName": "",
        }

        response = session.post(tenant_url + "/login/authenticate", data=payload, headers=h)
        r = response.json()

        if r['status'] == "error":
            print(r['message'])
            sys.exit()
        else:
            if "errorCode" in r['data'] and r['data']['errorCode'] == "mfa":
                # MFA handling code here (omitted for brevity)
                pass
            elif "errorCode" in r['data'] and r['data']['errorCode'] == "first_login":
                print("Expired password, change password needed")
                sys.exit()
            else:
                r = session.get(tenant_url + "/login/getToken", headers=h).json()
                token = self.gettoken(r['data'])

            r = session.get(tenant_url + "/login/isAccessAllowed", headers=h)
            r = session.post(tenant_url + "/login/postLoginAction", data={"token": token}, headers=h).json()

            if "privacynoticenotproceed" in r['data']:
                r = session.post(tenant_url + "/login/setFedRampProceed", data={"token": token}, headers=h).json()
                r = session.get(tenant_url + "/login/isAccessAllowed", headers=h)
                r = session.post(tenant_url + "/login/postLoginAction", data={"token": token}, headers=h).json()
        
        self.token = token
        self.cookie = response.cookies['ci_session']

    def get_headers(self):
        if not self.token or not self.cookie:
            raise ValueError("Not authenticated. Call login() first.")
        
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,nl;q=0.8",
            "Cookie": f"ci_session={self.cookie}",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": user_agent
        }
        return self.headers

netskope_auth = NetskopeAuth()

def cisco_update(ip_address, username, api_key, mac_address, data):
    try:
        response = requests.put(
            url=f"https://{ip_address}/api/v1/endpoint/{mac_address}",
            verify=False,
            headers={
                "Accept-Language": "en-US,en;q=0.9,nl;q=0.8",
                "Authorization": f"Basic {base64.b64encode(f'{username}:{api_key}'.encode()).decode()}",
                "Connection": "keep-alive",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={
                "customAttributes": data,
                "mac": mac_address,
            }
        )
        print(f'Response HTTP Status Code: {response.status_code}')
        print(f'Response HTTP Response Body: {response.content}')
        return response
    except requests.exceptions.RequestException:
        print('HTTP Request failed')

def cisco_create(ip_address, username, api_key, mac_address, data):
    try:
        response = requests.post(
            url=f"https://{ip_address}/api/v1/endpoint",
            verify=False,
            headers={
                "Accept-Language": "en-US,en;q=0.9,nl;q=0.8",
                "Authorization": f"Basic {base64.b64encode(f'{username}:{api_key}'.encode()).decode()}",
                "Connection": "keep-alive",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={
                "mac": mac_address,
                "customAttributes": data
            }
        )
        print(f'Response HTTP Status Code: {response.status_code}')
        print(f'Response HTTP Response Body: {response.content}')
        return response
    except requests.exceptions.RequestException:
        print('HTTP Request failed')

def get_device(username: str, hostname: str) -> Dict[str, Any]:
    try:
        response = requests.post(
            url=f"https://{netskope_auth.tenant}/rest",
            headers=netskope_auth.get_headers(),
            data=json.dumps({
                "__nsConfig": {},
                "method": "GET",
                "params": {
                    "fields": "host_info.hostname,userkey,host_info__os,username,last_event.status,last_event.status_v2,last_event.event,last_event.npa_status,user_id,_id,device_id,epdlp.runningStatus",
                    "offset": 0,
                    "sort": "-last_event__timestamp",
                    "async": False,
                    "resource": "device",
                    "proxy__service": {
                        "value": "DEVICE_SERVICE",
                        "sync": 0
                    },
                    "query": f"((username notlike '@prelogon.netskope.com') and (username like '{username}') and (host_info.hostname like '{hostname}'))"
                },
                "token": netskope_auth.token,
                "url": "/rest/device"
            })
        )
        return json.loads(response.content)
    except requests.exceptions.RequestException:
        print('HTTP Request failed')
        return {}

def get_device_details(device_id: str) -> Dict[str, Any]:
    try:
        response = requests.post(
            url=f"https://{netskope_auth.tenant}/rest",
            headers=netskope_auth.get_headers(),
            data=json.dumps({
                "__nsConfig": {},
                "method": "GET",
                "url": f"/rest/device/{device_id}",
                "params": {
                    "proxy__service": {
                        "value": "DEVICE_SERVICE"
                    },
                    "resource": f"device/{device_id}"
                },
                "token": netskope_auth.token
            })
        )
        return json.loads(response.content)
    except requests.exceptions.RequestException:
        print('HTTP Request failed')
        return {}

def get_uba_details() -> Dict[str, Any]:
    try:
        response = requests.post(
            url=f"https://{netskope_auth.tenant}/uba/fetchUsersAndStatistics",
            headers=netskope_auth.get_headers(),
            data=json.dumps({
                "offset": 0,
                "watchlist": "",
                "scoreType": "all",
                "searchText": "",
                "limit": 100,
                "token": netskope_auth.token,
                "lastXDays": 2
            })
        )
        return json.loads(response.content)
    except requests.exceptions.RequestException:
        print('HTTP Request failed')
        return {}

def is_valid_mac(mac: str) -> bool:
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))

def filter_mac_addresses(mac_addresses: List[str], excluded_macs: List[str], excluded_ouis: List[str]) -> List[str]:
    filtered_macs = [
        mac for mac in mac_addresses
        if is_valid_mac(mac) and
        mac not in excluded_macs and
        not any(mac.upper().startswith(oui.upper()) for oui in excluded_ouis)
    ]
    
    return list(dict.fromkeys(filtered_macs))  # This returns all unique MAC addresses

def get_confidence_score(username: str, uba_data: List[Dict[str, Any]]) -> int:
    for user in uba_data:
        if user['user'] == username:
            return user['confidenceScore']
    return None

def process_device(
    device: Dict[str, Any], 
    device_details: Dict[str, Any], 
    uba_data: List[Dict[str, Any]], 
    excluded_macs: List[str], 
    excluded_ouis: List[str],
    incident_info: Dict[str, Any]
) -> Dict[str, Any]:
    host_info = device['attributes']['host_info']
    user_info = device['attributes']['users'][0] if device['attributes']['users'] else {}
    details_host_info = device_details.get('host_info', {})
    
    mac_addresses = filter_mac_addresses(
        details_host_info.get('macAddresses', []),
        excluded_macs,
        excluded_ouis
    )
    
    record = {
        "netskope_device_id": device['attributes']['device_id'],
        "netskope_username": user_info.get('username'),
        "netskope_confidenceScore": get_confidence_score(user_info.get('username'), uba_data),
        "netskope_client_install_time": device_details.get('client_install_time'),
        "netskope_client_version": user_info.get('client_version'),
        "netskope_device_classification_status": user_info.get('device_classification_status'),
        "netskope_user_groups": user_info.get('user_groups', []),
        "netskope_os": details_host_info.get('os'),
        "netskope_os_version": details_host_info.get('os_version'),
        "netskope_serialNumber": details_host_info.get('serialNumber'),
        "netskope_device_make": details_host_info.get('device_make'),
        "netskope_device_model": details_host_info.get('device_model'),
        "netskope_hostname": details_host_info.get('hostname'),
        "netskope_last_hostinfo_update_timestamp": details_host_info.get('last_hostinfo_update_timestamp'),
        "netskope_macAddresses": mac_addresses,
        "netskope_incidentid": incident_info.get('incident_id', 'unknown'),
        "netskope_internalP": incident_info.get('internalip', 'unknown'),
        "netskope_egressIP": incident_info.get('egressip', 'unknown'),
        "netskope_severity": incident_info.get('incident_prio', 'unknown'),
        "netskope_incidenttype": incident_info.get('incident_severity', 'unknown'),
        "netskope_policyname": incident_info.get('policyname', 'unknown'),
        "netskope_createdby": "Netskope_CE"
    }
    
    return record

def main(message_json: dict, excluded_macs: List[str], excluded_ouis: List[str], ip_address: str, username: str, api_key: str):
    results = None
    cisco_response = None
    print(f"Processing devices with excluded MACs: {excluded_macs} and excluded OUIs: {excluded_ouis}")
    
    devices = get_device(message_json['Ur Normalized'], message_json['Hostname'])
    uba_details = get_uba_details()

    incident_info = {
        'incident_id': message_json.get('incident_id', 'unknown'),
        'internalip': message_json.get('internalip', 'unknown'),
        'egressip': message_json.get('egressip', 'unknown'),
        'incident_prio': message_json.get('incident_prio', 'unknown'),
        'incident_severity': message_json.get('incident_severity', 'unknown'),
        'policyname': message_json.get('policyname', 'unknown')
    }

    for device in devices.get('data', []):
        device_id = device['attributes']['device_id']
        print(f"\nProcessing device: {device_id}")
        
        device_details = get_device_details(device_id)
        processed_record = process_device(
            device, 
            device_details.get('data', {}).get('attributes', {}), 
            uba_details.get('results', []), 
            excluded_macs, 
            excluded_ouis,
            incident_info
        )

        print(f"Found {len(processed_record['netskope_macAddresses'])} unique MAC address(es) for this device")
        for mac in processed_record['netskope_macAddresses']:
            netskope_data = processed_record
            netskope_data_str = {k: str(v) for k, v in netskope_data.items()}
            cisco_response = cisco_update(ip_address, username, api_key, mac, netskope_data_str)
            if cisco_response.status_code == 404:
                #Entry does not exist
                cisco_response = cisco_create(ip_address, username, api_key, mac, netskope_data_str)
    return cisco_response

class cisco_ise(Provider):
    """Update Cisco ISE Devices"""
    base_url = "https://{domain}/api/v1/endpoint"
    site_url = "https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html"
    name = "cisco_ise"

    _required = {"required": ["api_key", "message", "ns_domain", "ns_username", "ns_password"]}
    _schema = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "minLength": 1, "title": "Cisco ISE API URL (i.e. 10.1.1.2 or europe-ISE101.corp.lan)"},
            "username": {"type": "string", "title": "Username for Cisco ISE API"},
            "api_key": {"type": "string", "title": "API key for Cisco ISE"},
            "ns_domain": {"type": "string", "minLength": 1, "title": "Netskope MGMT URL (i.e. example.goskope.com)"},
            "ns_username": {"type": "string", "title": "Netskope Username (Service account RO)"},
            "ns_password": {"type": "string", "title": "Netskope Password"},
            "message": {"type": "string", "title": "your message"},
        },
        "additionalProperties": False,
    }

    def _prepare_data(self, data: dict) -> dict:
        data['text'] = data.pop("message")
        return data

    def _send_notification(self, data: dict) -> Response:
        username = str(data.pop("username"))
        api_key = str(data.pop("api_key"))
        ip_address = data.pop("domain")
       
        message_json = json.loads(data['text'])

        # Configure the global netskope_auth instance
        ns_domain = str(data.pop("ns_domain"))
        ns_username = str(data.pop("ns_username"))
        ns_password = str(data.pop("ns_password"))
        netskope_auth.configure(ns_domain, ns_username, ns_password)
        
        excluded_macs = ["00:11:22:33:44:55"]
        excluded_ouis = ["00:00:00"]

        results = main(message_json, excluded_macs, excluded_ouis, ip_address, username, api_key)

        data = results
        response = results
        errors = None
        return self.create_response(data, response, errors)