import os
from dojo.acunetix.acunetix_api.acunetix_access import check_acunetix_api
from dojo.acunetix.forms import (
    TargetCreateForm, TargetsCreateForm, GetReportForm
)
from dojo.acunetix.another import *
from dojo.acunetix.acunetix_api.acunetix_exception import AcunetixException
from dojo.acunetix.acunetix_api.utils import ACUNETIX_URL   
from dojo.acunetix.acunetix_api.acunetix_target_and_scan import ApiGetScan
from dojo.models import (
    Endpoint, Test, Test_Type, Development_Environment, Engagement,
    Finding, CheckedScan
)
from dojo.acunetix.acunetix_api.acunetix_export import ApiGenerateExport, ApiGetExport

import logging
import time
import requests
import time
from datetime import datetime, timezone

from django.http import Http404
from django.shortcuts import render, redirect
from django.utils.timezone import make_aware


logger = logging.getLogger(__name__)

@check_acunetix_api
def create_target_and_start_scan(request):
    try:
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
                address = cleaned_data.get("address")
                try:
                    protocol, product = check_has_product(address)
                except Exception as e:
                    raise Http404(e)

                target = post_target_request(cleaned_data)
                target_id = target.get("target_id")

                scan = post_scan_request(target_id, scan_type)
                fill_statistic.apply_async(
                    args=[scan, protocol, product, address]
                )

                return redirect("active_scans")
            else:
                logger.error("Mistakes %s", target_form.errors)
                raise Http404("Invalid fill form")
        raise Http404("Is not available request")
    except AcunetixException as e:
        raise Http404(str(e))
        

@check_acunetix_api
def create_targets_and_start_scan(request):
    try:
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
                scans = {}
                for url in content:
                    target = TargetCreateForm(data={
                        "address": url,
                        **cleaned_data
                    })
                    if target.is_valid():
                        target_cleaned_data = target.cleaned_data
                        scan_type = target_cleaned_data.pop("scan_type")
                        address = target_cleaned_data.get("address")
                        try:
                            protocol, product = check_has_product(address)
                        except ValueError as e:
                            raise Http404(e)

                        target_created = post_target_request(target_cleaned_data)
                        target_id = target_created.get("target_id")
                        target_ids.append(target_id)

                        scan = post_scan_request(target_id, scan_type)
                        scans[scan["scan_id"]] = {
                            "scan": scan,
                            "protocol": protocol,
                            "product": product,
                            "address": address,
                            "delete": False
                        }
                target_group_id = target_group.get("group_id")
                set_target_to_group(target_ids, target_group_id)

                fill_statistic_for_files.apply_async(args=[scans])

                return redirect("active_scans")
            else:
                logger.error("Mistakes %s", targets_form.errors)
                raise Http404("Invalid fill form")
        raise Http404("Is not available request")
    except AcunetixException as e:
        raise Http404(str(e))

@check_acunetix_api
def get_active_scans(request):
    scans = get_scans_in_processing()
    return create_template_scan(request, scans)

@check_acunetix_api
def get_scans(request):
    scans = get_all_scans()
    return create_template_scan(request, scans)

@check_acunetix_api
def import_reports(request):
    if request.method == "POST":
        form = GetReportForm(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            type_scan = cleaned_data["type_scan"]
            periodic_in_seconds = cleaned_data["periodic"]
            type_import = cleaned_data["type_import"]
            schedule_task(type_import, periodic_in_seconds, type_scan)

            return render(request, "dojo/acunetix_report.html", {"form": form})
        else:
            raise Http404("Invalid form")

    if request.method == "GET":
        form = GetReportForm()
        return render(request, "dojo/acunetix_report.html", {"form": form})
    
@check_acunetix_api
def delete_target_groups(request):
    ...