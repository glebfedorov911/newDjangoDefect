import logging
import requests

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_request(method, url, **kwargs):
    logging.info(f"{method} {url} - Payload: {kwargs.get('json')}")
    response = requests.request(method, url, verify=False, **kwargs)
    logging.info(f"Response [{response.status_code}]: {response.text}")
    return response

def get_report(report_id):
    return log_request("GET", f"https://192.168.1.143:3443/api/v1/reports/{report_id}")

def create_report(payload):
    return log_request("POST", "https://192.168.1.143:3443/api/v1/reports", json=payload)

def get_report_templates():
    return log_request("GET", "https://192.168.1.143:3443/api/v1/report_templates")

def get_scan_results(scan_id):
    return log_request("GET", f"https://192.168.1.143:3443/api/v1/scans/{scan_id}/results")

def post_scan_vulnerabilities(scan_id, payload):
    return log_request("POST", f"https://192.168.1.143:3443/api/v1/scans/{scan_id}/results/{scan_id}/vulnerabilities", json=payload)

def get_scans():
    return log_request("GET", "https://192.168.1.143:3443/api/v1/scans")

def get_result(result_id):
    return log_request("GET", f"https://192.168.1.143:3443/api/v1/results/{result_id}")

def create_scan(payload):
    return log_request("POST", "https://192.168.1.143:3443/api/v1/scans", json=payload)

def create_target(payload):
    return log_request("POST", "https://192.168.1.143:3443/api/v1/targets", json=payload)

def get_users():
    return log_request("GET", "https://192.168.1.143:3443/api/v1/users")

setup_logging()
