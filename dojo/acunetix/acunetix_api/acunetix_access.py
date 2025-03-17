from django.http import HttpResponse
import requests

import logging
import functools

from dojo.acunetix.acunetix_api.acunetix_exception import AcunetixException
from dojo.acunetix.acunetix_api.utils import (
    ACUNETIX_URL, HEADERS
)

logger = logging.getLogger(__name__)

def is_available_acunetix_api() -> None:
    try:
        logging.info("Trying to connect to acunetix api")
        response = requests.get(f"{ACUNETIX_URL}/users", headers=HEADERS, 
                                timeout=5, verify=False)
        logging.info("Status: %s", response.status_code)
        response.raise_for_status()
        logging.info("Success connection to acunetix api")
    except requests.exceptions.Timeout as e:
        logger.exception(e)
        raise AcunetixException("Timeout to connect acunetix. Not available", 400)
    except requests.exceptions.HTTPError as e:
        logger.exception(e)
        raise AcunetixException("Bad requests. Status 40x. Not available", 400)
    except Exception as e:
        logger.exception(e)
        raise AcunetixException("Internal Server Error", 500)

def check_acunetix_api(func):
    
    
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        try:
            is_available_acunetix_api()
        except AcunetixException as e:
            logging.exception(e)
            return HttpResponse(f"Acunetix is not available: {e}", status=e.get_error_code())

        return func(*args, **kwargs)
    
    return _wrapper