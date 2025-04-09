import os
from dojo.acunetix.acunetix_api.acunetix_access import is_available_acunetix_api
from dojo.acunetix.forms import (
    TargetCreateForm, TargetsCreateForm, GetReportForm, AddAcunetixServerForm, AcunetixServerSelectForm
)
from dojo.acunetix.another import *
from dojo.acunetix.acunetix_api.acunetix_exception import AcunetixException
from dojo.acunetix.acunetix_api.utils import ACUNETIX_URL   
from dojo.acunetix.acunetix_api.acunetix_target_and_scan import ApiGetScan
from dojo.acunetix.acunetix_api.acunetix_export import ApiGenerateExport, ApiGetExport
from dojo.models import AcunetixServers

import logging
import time
import requests
import time
from datetime import datetime, timezone

from django.http import Http404
from django.urls import reverse
from django.shortcuts import render, redirect
from django.utils.timezone import make_aware
from django_celery_beat.models import PeriodicTask


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) 

file_handler = logging.FileHandler('./dojo/acunetix/acunetix.log', mode='a', encoding='utf-8')  
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

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
                acunetix_server = cleaned_data.pop("server")
                server, token = get_data_server(acunetix_server)
                is_available_acunetix_api(server, token)
                scan_type = cleaned_data.pop("scan_type")
                address = cleaned_data.get("address")
                try:
                    protocol, product = check_has_product(address)
                except Exception as e:
                    logger.warning(f"Not found product {address}")
                    # raise Http404(e)
                else:

                    target = post_target_request(server, token, cleaned_data)
                    target_id = target.get("target_id")

                    scan = post_scan_request(server, token, target_id, scan_type)
                    fill_statistic.apply_async(
                        args=[server, token, scan, protocol, product, address]
                    )

                    return redirect(f"indepo/scans/active?server={acunetix_server.id}")
            else:
                logger.error("Mistakes %s", target_form.errors)
                raise Http404("Invalid fill form")
        raise Http404("Is not available request")
    except AcunetixException as e:
        raise Http404(str(e))
        


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
                cleaned_data_server = cleaned_data.pop("server")
                server, token = get_data_server(cleaned_data_server)
                is_available_acunetix_api(server, token)
                file = cleaned_data.pop("addresses")
                group_name = cleaned_data.pop("name")
                content = read_file(file)
                
                target_ids = []
                valid_product = {}
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
                            logger.warning(f"Not found product {address}")
                            # raise Http404(e)

                        target_created = post_target_request(
                            server=server, 
                            token=token, 
                            target=target_cleaned_data)
                        target_id = target_created.get("target_id")
                        target_ids.append(target_id)
    
                        scan = post_scan_request(
                            server=server, 
                            token=token, 
                            target_id=target_id, 
                            profile_id=scan_type)
                        valid_product[target_id] = {
                            "protocol": protocol,
                            "product": product,
                            "address": address,
                            "delete": False
                        }
                        
                for target_id in target_ids:
                    scans[scan["scan_id"]] = {
                        "scan": scan,
                        "protocol": valid_product[target_id]["protocol"],
                        "product": valid_product[target_id]["product"],
                        "address": valid_product[target_id]["address"],
                        "delete": valid_product[target_id]["delete"]
                    }
                target_group = create_target_group(server=server, token=token, name=group_name)
                target_group_id = target_group.get("group_id")
                set_target_to_group(server, token, target_ids, target_group_id)

                fill_statistic_for_files.apply_async(args=[server, token, scans])

                return redirect(f"indepo/scans/active?server={cleaned_data_server.id}")
            else:
                logger.error("Mistakes %s", targets_form.errors)
                raise Http404("Invalid fill form")
        raise Http404("Is not available request")
    except AcunetixException as e:
        raise Http404(str(e))

def get_scans_by_func(request, func, server, token):
    is_available_acunetix_api(server, token)
    scans = func(server, token)
    return create_template_scan(request, scans)

def get_scans_by_type(request, func, server_id=None):
    try:
        if server_id:
            acunetix_server = AcunetixServers.objects.get(id=server_id)
            server, token = get_data_server(acunetix_server)
            return get_scans_by_func(request, func, server, token)
        if request.method == "POST":
            form = AcunetixServerSelectForm(request.POST)
            if form.is_valid(): 
                cleaned_data = form.cleaned_data
                server, token = get_data_server(cleaned_data.pop("server"))
            else:
                raise Http404("Invalid form data")
            return get_scans_by_func(request, func, server, token)
        if request.method == "GET":
            form = AcunetixServerSelectForm()
            return render(request, "dojo/acunetix_target_and_scan_table.html", {"has_form": True, "form": form})
    except AcunetixException as e:
        raise Http404(str(e))
    raise Http404("Not found method")

def get_active_scans(request):
    server_id=request.GET.get("server")
    return get_scans_by_type(request, get_scans_in_processing, server_id)

def get_scans(request):
    return get_scans_by_type(request, get_all_scans)

def import_reports(request):
    try:
        if request.method == "POST":
            form = GetReportForm(request.POST)
            if form.is_valid():
                cleaned_data = form.cleaned_data
                type_scan = cleaned_data["type_scan"]
                periodic_in_seconds = cleaned_data["periodic"]
                type_import = cleaned_data["type_import"]                
                server, token = get_data_server(cleaned_data.pop("server"))
                is_available_acunetix_api(server, token)
                schedule_task(server, token, type_import, periodic_in_seconds, type_scan)

                # return render(request, "dojo/acunetix_report.html", {"form": form})
                return redirect("periodic_task")
            else:
                raise Http404("Invalid form")
    except AcunetixException as e:
        raise Http404(str(e))

    if request.method == "GET":
        form = GetReportForm()
        return render(request, "dojo/acunetix_report.html", {"form": form})
    

def select_target_group(request):
    if request.method == "GET":
        form = AcunetixServerSelectForm()
        return render(request, "dojo/acunetix_select_target.html", {"form": form})
    if request.method == "POST":
        form = AcunetixServerSelectForm(request.POST)
        if form.is_valid():
            server = form.cleaned_data.get("server")
            return redirect(reverse("target_groups", kwargs={"id": server.id}))
    raise Http404("Invalid form data")

def target_groups(request, id):
    server = AcunetixServers.objects.get(id=id)
    server, token = get_data_server(server)
    if request.method == "POST":
        group_ids = get_splited_items(request)
        group_id_list = {"group_id_list": group_ids}
        delete_target_groups_by_ids(server=server, token=token, group_id_list=group_id_list)

    groups = get_all_target_groups(server, token).get("groups")
    groups_context = [
        {
            "name": group["name"],
            "group_id": group["group_id"],
            "critical": group["vuln_count"]["critical"],
            "high": group["vuln_count"]["high"],
            "info": group["vuln_count"]["info"],
            "low": group["vuln_count"]["low"],
            "medium": group["vuln_count"]["medium"],
        } for group in groups
    ]
    paginate_groups = paginate(request, groups_context)

    return render(request, "dojo/acunetix_target_groups.html", {"groups": paginate_groups})


def periodic_task(request):
    if request.method == "POST":
        data = request.POST
        active_ids = [int(i) for i in data.getlist('active[]', [])]
        inactive_ids = [int(i) for i in data.getlist('inactive[]', [])]
        
        PeriodicTask.objects.filter(id__in=active_ids).update(enabled=True)
        PeriodicTask.objects.filter(id__in=inactive_ids).update(enabled=False)

        return redirect("periodic_task")
    
    periodic_tasks = PeriodicTask.objects.all()
    periodic_tasks_context = [
        {
            "id": periodic_task.id,
            "name": periodic_task.name,
            "enabled": periodic_task.enabled,
            "interval": periodic_task.interval
        }
    for periodic_task in periodic_tasks if "Scan Parser" in periodic_task.name]
    periodic_tasks_context = paginate(request, periodic_tasks_context)

    return render(request, "dojo/acunetix_delete_reports.html", {"periodic_tasks": periodic_tasks_context})



def add_acunetix_server(request):
    if request.method == "POST":
        form = AddAcunetixServerForm(request.POST)
        if form.is_valid():
            form.save()
        else:
            raise Http404("Invalid form")
        return redirect("acunetix_servers")
        
    form = AddAcunetixServerForm()
    return render(request, "dojo/acunetix_add_server.html", {"form": form})

def acunetix_servers(request):
    print("fdskfdskkfdskfdksfdkfdks", request.method)
    if request.method == "POST":
        delete_data = request.POST.getlist("deleteData[]")
        AcunetixServers.objects.filter(id__in=delete_data).delete()
    servers = AcunetixServers.objects.all()
    servers = paginate(request, servers)
    return render(request, "dojo/acunetix_show_servers.html", {"servers": servers})