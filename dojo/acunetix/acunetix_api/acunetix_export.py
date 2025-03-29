from dojo.acunetix.acunetix_api.acunetix_request_mixin import ApiMixin
from dojo.acunetix.acunetix_api.utils import ACUNETIX_TOKEN, ACUNETIX_URL


class ApiGenerateExport(ApiMixin):


    def __init__(
            self,
            json: dict,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{ACUNETIX_URL}/exports"
        super().__init__("POST", url, api_key, json=json)

class ApiGetExport(ApiMixin):


    def __init__(
            self,
            export_id: str,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{ACUNETIX_URL}/exports/{export_id}"
        super().__init__("GET", url, api_key)