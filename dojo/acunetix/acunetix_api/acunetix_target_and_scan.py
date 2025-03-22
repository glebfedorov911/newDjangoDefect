from dojo.acunetix.acunetix_api.acunetix_request_mixin import ApiMixin
from dojo.acunetix.acunetix_api.utils import ACUNETIX_TOKEN, ACUNETIX_URL


class ApiTargetAddTarget(ApiMixin):


    def __init__(
            self,
            target: dict,
            api_key: str = ACUNETIX_TOKEN,
    ):
        url = f"{ACUNETIX_URL}/targets"
        super().__init__("POST", url, api_key, json=target)

class ApiScanStart(ApiMixin):
    

    def __init__(
            self,
            scan: dict,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{ACUNETIX_URL}/scans"
        super().__init__("POST", url, api_key, json=scan)