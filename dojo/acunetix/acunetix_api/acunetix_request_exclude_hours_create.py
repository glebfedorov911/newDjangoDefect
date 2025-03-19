from dojo.acunetix.acunetix_api.acunetix_request_mixin import ApiMixin
from dojo.acunetix.acunetix_api.utils import ACUNETIX_TOKEN


class ApiCreateExcludeHours(ApiMixin):

    
    def __init__(
            self,
            body_,
            api_key: str = ACUNETIX_TOKEN
    ):
        super().__init__("POST", api_key, json=body_.body())