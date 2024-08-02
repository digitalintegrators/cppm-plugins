from . import (
    cisco_ise,
    aruba_cppm
)

_all_providers = {
    "cisco_ise": cisco_ise.cisco_ise,
    "aruba_cppm": aruba_cppm.aruba_cppm
}
