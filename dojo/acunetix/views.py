from dojo.acunetix.acunetix_api.acunetix_access import check_acunetix_api
from dojo.acunetix.acunetix_api.acunetix_target_and_scan import (
    ApiTargetAddTarget, ApiScanStart, ApiTargetGroupCreate, 
    ApiTargetGroupSetTargets, ApiGetScans
)
from dojo.acunetix.forms import (
    TargetCreateForm, TargetsCreateForm
)

import json
import logging
import uuid

from django.http import HttpResponse, Http404
from django.shortcuts import render


logger = logging.getLogger(__name__)

@check_acunetix_api
def create_target_and_start_scan(request):
    
    logger.info(f"%s Request to acunetix/targets/create", request.method)
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
    logger.info(f"%s Request to acunetix/targets/create-any", request.method)
    if request.method == "GET":
        targets_form = TargetsCreateForm()
        return render(
            request,
            "dojo/acunetix_target_and_scan_create.html",
            {"target_form": targets_form}
        )
    if request.method == "POST":
        targets_form = TargetsCreateForm(request.POST, request.FILES)

        if targets_form.is_valid():
            cleaned_data = targets_form.cleaned_data
            file = cleaned_data.pop("addresses")
            group_name = cleaned_data.pop("name")
            content = read_file(file)
            
            target_group = create_target_group(group_name)
            target_ids = []
            for url in content:
                target = TargetCreateForm(data={
                    "address": url,
                    **cleaned_data
                })
                if target.is_valid():
                    target_cleaned_data = target.cleaned_data
                    scan_type = target_cleaned_data.pop("scan_type")
                    target_created = post_target_request(target_cleaned_data)
                    target_id = target_created.get("target_id")
                    target_ids.append(target_id)

                    post_scan_request(target_id, scan_type)

            target_group_id = target_group.get("group_id")
            set_target_to_group(target_ids, target_group_id)

            return HttpResponse(str(target_ids)) 
        else:
            logger.error("Mistakes %s", targets_form.errors)
            raise Http404()
    raise Http404()

def get_active_scans(request):
    result = str(get_scans_in_processing())
    return HttpResponse(result)

def post_target_request(target: dict) -> dict:
    target_api = ApiTargetAddTarget(target)
    logger.info("Do request to create target")
    return _request(target_api)

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
    return _request(scan_api)

def _request(api) -> dict:
    result = api.do()
    logger.info("Success request %s", result)
    try:
        return json.loads(result)
    except:
        ...

def read_file(file) -> list:
    return file.read().decode("utf-8").split(";")

def create_target_group(name: str):
    json = {
        "group_id": str(uuid.uuid4()),
        "name": name
    }
    api = ApiTargetGroupCreate(json)
    return _request(api)

def set_target_to_group(target_ids: list, group_id: str):
    json = {
        "target_id_list": target_ids
    }
    api = ApiTargetGroupSetTargets(json, group_id=group_id)
    return _request(api)

def get_scans_in_processing():
    api = ApiGetScans()
    json = _request(api)
    return [
        scan for scan in json["scans"] 
        if scan["current_session"]["status"] == "processing"
    ]