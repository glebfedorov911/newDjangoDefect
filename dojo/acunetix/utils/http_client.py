import requests
import urllib3
import json as json_lib


urllib3.disable_warnings()

class HttpClientRequest:


    def __init__(
            self,
            url: str,
            method: str,
            /,
            json: dict | None = None,
            headers: dict | None = None,
            proxy: dict | None = None
    ):
        self.url = url
        self.method = method
        self.json = json
        self.headers = headers
        self.proxy = proxy

    def send_request(self) -> str:
        try:
            return self._send_request()
        except requests.exceptions.RequestException as e:
            raise ValueError("Bad request")
        
    def _send_request(self) -> str:
        response = requests.request(self.method, self.url, json=self.json, 
                                    headers=self.headers, proxies=self.proxy,
                                    verify=False)
        
        try:
            response_json = json_lib.loads(response.text)
            if "code" in response_json:
                raise ValueError(response_json["message"])
        except json_lib.JSONDecodeError:
            ...

        return response.text
    
class GetRequestClient(HttpClientRequest):


    def __init__(self, url: str, headers: dict | None = None, proxy: dict | None = None):
        super().__init__(url, "GET", headers=headers, proxy=proxy)

class PostRequestClient(HttpClientRequest):


    def __init__(self, url: str, json: dict | None = None, headers: dict | None = None, proxy: dict | None = None):
        super().__init__(url, "POST", json=json, headers=headers, proxy=proxy)

class PutRequestClient(HttpClientRequest):


    def __init__(self, url: str, json: dict | None, headers: dict | None = None, proxy: dict | None = None):
        super().__init__(url, "PUT", json=json, headers=headers, proxy=proxy)

class PatchRequestClient(HttpClientRequest):


    def __init__(self, url: str, json: dict | None, headers: dict | None = None, proxy: dict | None = None):
        super().__init__(url, "PATCH", json=json, headers=headers, proxy=proxy)

class DeleteRequestClient(HttpClientRequest):


    def __init__(self, url: str, headers: dict | None = None, proxy: dict | None = None):
        super().__init__(url, "DELETE", headers=headers, proxy=proxy)

class RequestClientFactory:


    def create_new_client(self, method, /, **kwargs):
        method = method.lower()
        if method == "get":
            return GetRequestClient(**kwargs)
        elif method == "post":
            return PostRequestClient(**kwargs)
        elif method == "put":
            return PutRequestClient(**kwargs)
        elif method == "patch":
            return PatchRequestClient(**kwargs)
        elif method == "delete":
            return DeleteRequestClient(**kwargs)
        else:
            raise ValueError(f"Not found {method} method")