from dojo.acunetix.acunetix_api.acunetix_request_mixin import ApiMixin
from dojo.acunetix.acunetix_api.utils import ACUNETIX_URL, ACUNETIX_TOKEN


class ApiGetResultByScan(ApiMixin):


    def __init__(
            self,
            scan_id: str,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{ACUNETIX_URL}/scans/{scan_id}/results"
        super().__init__("GET", url, api_key)

class ApiGetCrawlData(ApiMixin):


    def __init__(
            self,
            scan_id: str, 
            result_id: str,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{ACUNETIX_URL}/scans/{scan_id}/results/{result_id}/crawldata"
        super().__init__("GET", url, api_key)

class ApiGetCrawlDataChildren(ApiMixin):


    def __init__(
            self,
            scan_id: str, 
            result_id: str,
            loc_id: str,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{ACUNETIX_URL}/scans/{scan_id}/results/{result_id}/crawldata/{loc_id}/children"
        super().__init__("GET", url, api_key)

class ApiGetVulnerabilities(ApiMixin):

    
    def __init__(
            self,
            scan_id: str, 
            result_id: str,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{ACUNETIX_URL}/scans/{scan_id}/results/{result_id}/vulnerabilities"
        super().__init__("GET", url, api_key)