from dojo.acunetix.utils.http_client import RequestClientFactory
from dojo.acunetix.acunetix_api.utils import ACUNETIX_URL, ACUNETIX_TOKEN

class ApiMixin:


    def __init__(
            self,
            method: str,
            url: str = ACUNETIX_URL,
            api_key: str = ACUNETIX_TOKEN,
            /,
            json: dict | None = None
    ):
        self.url = url

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
            return self.http_client.send_request()
        except ValueError as e:
            raise e