import os


ACUNETIX_TOKEN = os.getenv("ACUNETIX_TOKEN")
ACUNETIX_URL = os.getenv("ACUNETIX_URL")

HEADERS = {
    'X-Auth': ACUNETIX_TOKEN
}