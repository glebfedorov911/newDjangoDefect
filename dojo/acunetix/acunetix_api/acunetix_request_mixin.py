from dojo.acunetix.utils.http_client import RequestClientFactory
from dojo.acunetix.acunetix_api.utils import ACUNETIX_URL, ACUNETIX_TOKEN

class ApiMixin:


    def __init__(
            self,
            method: str,
            api_key: str = ACUNETIX_TOKEN,
            /,
            json: dict | None = None
    ):
        self.url = f"{ACUNETIX_URL}/excluded_hours_profiles"

        self.headers = {
            "X-Auth": api_key
        }
        
        factory = RequestClientFactory()
        if json:
            self.http_client = factory.create_new_client(
                method, url=self.url, headers=self.headers, json=json
            )
        else:
            self.http_client = factory.create_new_client(
                method, url=self.url, headers=self.headers
            )


    def do(self):
        try:
            self.http_client.send_request()
        except ValueError as e:
            raise e