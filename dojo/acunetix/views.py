from dojo.acunetix.acunetix_api.acunetix_access import check_acunetix_api
from dojo.acunetix.acunetix_api.acunetix_target_and_scan import (
    ApiTargetAddTarget, ApiScanStart
)
from dojo.acunetix.forms import TargetCreateForm, TargetsCreateForm

import json
import logging

from django.http import HttpResponse, Http404
from django.shortcuts import render


logger = logging.getLogger(__name__)

@check_acunetix_api
def create_target_and_start_scan(request):
    
    logger.info(f"%s Request to acunetix/targets/create-target", request.method)
    if request.method == "GET":
        target_form = TargetCreateForm()
        return render(
            request,
            "dojo/acunetix_target_and_scan_create.html",
            {"target_form": target_form}
        )
    if request.method == "POST":
        target_form = TargetCreateForm(request.POST)
        
        if target_form.is_valid():
            cleaned_data = target_form.cleaned_data
            scan_type = cleaned_data.pop("scan_type")

            target = post_target_request(cleaned_data)
            target_id = target.get("target_id")

            scan = post_scan_request(target_id, scan_type)
            return HttpResponse(scan)
        else:
            logger.error("Mistakes %s", target_form.errors)
            raise Http404()
    raise Http404()

def create_targets_and_start_scan(request):
    logger.info(f"%s Request to acunetix/targets/create-any-targets", request.method)
    if request.method == "GET":
        targets_form = TargetsCreateForm()
        return render(
            request,
            "dojo/acunetix_target_and_scan_create.html",
            {"target_form": targets_form}
        )
    if request.method == "POST":
        print(request.POST)
        print(request.FILES)
        targets_form = TargetsCreateForm(request.POST, request.FILES)

        if targets_form.is_valid():
            cleaned_data = targets_form.cleaned_data
            file = cleaned_data.pop("addresses")
            content = read_file(file)
            
            target_ids = []
            for url in content:
                target = TargetCreateForm(data={
                    "address": url,
                    **cleaned_data
                })
                target_created = post_target_request(target)
                target_id = target_created.get("target_id")
                target_ids.append(target_id)
            return HttpResponse(str(target_ids)) 
        else:
            logger.error("Mistakes %s", targets_form.errors)
            raise Http404()
    raise Http404()


def post_target_request(target: dict) -> dict:
    target_api = ApiTargetAddTarget(target)
    logger.info("Do request to create target")
    return post(target_api)

def post_scan_request(target_id: str, profile_id: str) -> dict:
    scan = {
        "target_id": target_id,
        "profile_id": profile_id,
        "schedule": {
            "disable": False,
            "start_date": None,
            "time_sensitive": False
        }
    }

    scan_api = ApiScanStart(scan)
    logger.info("Do request to start scan")
    return post(scan_api)

def post(api) -> dict:
    result = api.do()
    logger.info("Success request %s", result)
    return json.loads(result)

def read_file(file) -> list:
    return file.read().decode("utf-8").split(";")