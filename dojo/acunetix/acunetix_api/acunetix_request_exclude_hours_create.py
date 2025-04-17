from dojo.acunetix.acunetix_api.acunetix_request_mixin import ApiMixin
from dojo.acunetix.acunetix_api.utils import ACUNETIX_TOKEN, ACUNETIX_URL


class ApiCreateExcludeHours(ApiMixin):

    
    def __init__(
            self,
            body_,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN
    ):
        super().__init__("POST", api_key, json=body_.body())