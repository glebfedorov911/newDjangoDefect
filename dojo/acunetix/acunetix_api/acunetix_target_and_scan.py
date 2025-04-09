from dojo.acunetix.acunetix_api.acunetix_request_mixin import ApiMixin
from dojo.acunetix.acunetix_api.utils import ACUNETIX_TOKEN, ACUNETIX_URL


class ApiTargetAddTarget(ApiMixin):


    def __init__(
            self,
            target: dict,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN,
    ):
        url = f"{url}/targets"
        super().__init__("POST", url, api_key, json=target)

class ApiScanStart(ApiMixin):
    

    def __init__(
            self,
            scan: dict,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{url}/scans"
        super().__init__("POST", url, api_key, json=scan)

class ApiTargetGroupCreate(ApiMixin):
    

    def __init__(
            self,
            target_group: dict,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{url}/target_groups"
        super().__init__("POST", url, api_key, json=target_group)

class ApiTargetGroupSetTargets(ApiMixin):
    

    def __init__(
            self,
            list_targets: dict,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN,
            **kwargs
    ):
        group_id = kwargs.get("group_id")
        url = f"{url}/target_groups/{group_id}/targets"
        super().__init__("POST", url, api_key, json=list_targets)

class ApiGetScans(ApiMixin):
    
    
    def __init__(
            self,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{url}/scans"
        super().__init__("GET", url, api_key)

class ApiGetScan(ApiMixin):
    
    
    def __init__(
            self,
            scan_id: str,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{url}/scans/{scan_id}"
        super().__init__("GET", url, api_key)

class ApiGetVulnerabilities(ApiMixin):
    

    def __init__(
            self,
            scan_id: str,
            result_id: str,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ): 
        url = f"{url}/scans/{scan_id}/results/{result_id}/vulnerabilities"
        super().__init__("GET", url, api_key)

class ApiGetTargetGroups(ApiMixin):
    

    def __init__(
            self,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{url}/target_groups"
        super().__init__("GET", url, api_key)

class ApiDeleteTargetGroups(ApiMixin):


    def __init__(
            self,
            list_target_groups: dict,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ):
        url = f"{url}/target_groups/delete"
        print(url, list_target_groups, 'fskjdfdsjdfsjfdsj')
        super().__init__("POST", url, api_key, json=list_target_groups)