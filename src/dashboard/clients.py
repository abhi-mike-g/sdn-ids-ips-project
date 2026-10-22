"""HTTP boundaries between the independent dashboard and controller processes."""
import requests


class ServiceUnavailable(RuntimeError):
    pass


class ServiceClient:
    def __init__(self, base_url, timeout=2):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    def request(self, method, path, **kwargs):
        try:
            response = requests.request(method, self.base_url + path, timeout=self.timeout, **kwargs)
            return response.json(), response.status_code
        except (requests.RequestException, ValueError) as exc:
            raise ServiceUnavailable(str(exc)) from exc

    def get(self, path):
        data, status = self.request('GET', path)
        if status != 200:
            raise ServiceUnavailable(data.get('error', 'Service unavailable'))
        return data
