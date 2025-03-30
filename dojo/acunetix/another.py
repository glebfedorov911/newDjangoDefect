import os
import requests
from dojo.acunetix.acunetix_api.acunetix_export import ApiGenerateExport, ApiGetExport
from dojo.acunetix.acunetix_api.acunetix_target_and_scan import (
    ApiGetScan, ApiTargetAddTarget, ApiScanStart, ApiTargetGroupCreate, 
    ApiTargetGroupSetTargets, ApiGetScans, ApiGetTargetGroups, ApiDeleteTargetGroups
)
from dojo.acunetix.acunetix_api.acunetix_statistics import (
    ApiGetCrawlDataChildren, ApiGetCrawlData, ApiGetResultByScan,
    ApiGetVulnerabilities
)
from dojo.acunetix.acunetix_api.utils import ACUNETIX_URL
from dojo.celery import app
from dojo.models import (
    CheckedScan, Endpoint, Product, Test_Type, 
    Engagement, Finding, Test, Development_Environment,
)

from celery.schedules import crontab, schedule

from datetime import datetime, timezone, timedelta
import time
import json
import logging
import uuid

from django.shortcuts import render
from django.core.paginator import Paginator
from django_celery_beat.models import PeriodicTask, IntervalSchedule


logger = logging.getLogger(__name__)

def paginate(request, context):
    page = request.GET.get("page", 1)
    paginator = Paginator(context, 10)
    return paginator.get_page(page)

def create_template_scan(request, scans):
    scans_context = create_context_scans(scans)
    scans_page = paginate(request, scans_context)

    return render(request, "dojo/acunetix_target_and_scan_table.html", {"scans": scans_page})

def create_context_scans(scans):
    return [{
        "progress": scan["current_session"]['progress'],
        "critical": scan["current_session"]["severity_counts"]["critical"],
        "high": scan["current_session"]["severity_counts"]["high"],
        "info": scan["current_session"]["severity_counts"]["info"],
        "low": scan["current_session"]["severity_counts"]["low"],
        "medium": scan["current_session"]["severity_counts"]["medium"],
        "status": scan["current_session"]["status"],
        "scan_id": scan["scan_id"],
        "address": scan["target"]["address"]
    } for scan in scans]

def post_target_request(target: dict) -> dict:
    target_api = ApiTargetAddTarget(target)
    logger.info("Do request to create target")
    return do_request(target_api)

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
    
    json = do_request(scan_api)
    update_args_in_periodic_task()
    return json

def do_request(api) -> dict:
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
    return do_request(api)

def set_target_to_group(target_ids: list, group_id: str):
    json = {
        "target_id_list": target_ids
    }
    api = ApiTargetGroupSetTargets(json, group_id=group_id)
    return do_request(api)

def get_scans_in_processing():
    scans = get_scans_mixin()
    return [
        scan for scan in scans 
        if scan["current_session"]["status"] == "processing"
    ]

def get_all_scans():
    return get_scans_mixin()

def get_scans_mixin():
    api = ApiGetScans()
    json = do_request(api)
    return json["scans"]

def check_has_product(address):
    protocol = "https"
    if "https://" in address:
        protocol = "https"
        address = address.replace("https://", "")
    if "http://" in address:
        protocol = "http"
        address = address.replace("http://", "")
    if "ftp://" in address:
        protocol = "ftp"
        address = address.replace("ftp://", "")
    address = address.replace("/", "")
    
    splited_address = address.split(".")
    while splited_address:
        address = '.'.join(splited_address)
        try:
            return protocol, Product.objects.get(name=address)
        except Product.DoesNotExist:
            ...
        splited_address.pop(0)
    raise ValueError("Not found Product. Will create it")

def get_all_endpoints(scan_id):
    result_id = get_result_id_by_scan(scan_id)

    api = ApiGetCrawlData(scan_id, result_id)
    json = do_request(api)

    loc_ids = [location["loc_id"] for location in json["locations"]]
    endpoints = [location["path"][1:] for location in json["locations"]]
    for loc_id in loc_ids:
        api_loc = ApiGetCrawlDataChildren(scan_id, result_id, loc_id)
        json_loc = do_request(api_loc)
        for location in json_loc["locations"]:
            loc_ids.append(location['loc_id'])
            endpoints.append(location['path'][1:])

    return endpoints

def get_vulnerabilities(scan_id):
    SEVERITY = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
    result_id = get_result_id_by_scan(scan_id)

    api = ApiGetVulnerabilities(scan_id, result_id)
    vulnerabilities = do_request(api)

    return [
        {
        "vt_name": vuln["vt_name"],
        "type": SEVERITY[str(vuln["severity"])],
        "desc": vuln["vt_name"],
        "mark": f"S{vuln['severity']}"
        } for vuln in vulnerabilities["vulnerabilities"]
    ]

def get_result_id_by_scan(scan_id):
    result_api = ApiGetResultByScan(scan_id)
    return do_request(result_api)["results"][0]["result_id"]

@app.task
def fill_statistic_for_files(scans):
    while not all([scans[scan]['delete'] for scan in scans]):
        for scan in scans:
            if not scans[scan]["delete"] and fill_statistic.apply_async(
                args=[
                    scans[scan]["scan"], scans[scan]["protocol"], 
                    scans[scan]["product"], scans[scan]["address"]
                ]
            ):
                scans[scan]["delete"] = True
@app.task
def fill_statistic(scan: dict, protocol: str, product: Product, address: str):
    scan_id = scan["scan_id"]
    while True:
        api = ApiGetScan(scan_id)
        scan_result = do_request(api)
        scan_status = scan_result['current_session']["progress"]
        if str(scan_status) == "100":
            break
        time.sleep(10)

    endpoints = get_all_endpoints(scan_id)
    endpoints_objs = []
    for endpoint in endpoints:
        print("создаем эндпоинты")
        endpoint_obj = Endpoint.objects.get_or_create(
            protocol=protocol,
            host=product.name,
            path=endpoint,
            product=product
        )
        if endpoint_obj[1]:
            endpoints_objs.append(endpoint_obj[0].id)
    
    test_type = Test_Type.objects.get(name="Web Application Test")
    scan_type = "FULL"
    env = Development_Environment.objects.get(name="Development")
    start_time = datetime.fromisoformat(scan_result["current_session"]["start_date"]).date()
    end_time = datetime.now(timezone.utc).date()

    engagement = Engagement.objects.get_or_create(
        product=product,
        status="Completed",
        target_start=start_time,
        target_end=end_time
    )

    test = Test.objects.get_or_create(
        engagement=engagement[0],
        test_type=test_type,
        scan_type=scan_type,
        environment=env,
        title=address,
        target_start=start_time,
        target_end=end_time
    )

    vulnerabilites = get_vulnerabilities(scan_id)
    for vuln in vulnerabilites:
        finding, created = Finding.objects.get_or_create(
            title=address,
            cvssv3="",
            cve=vuln["vt_name"][:50],
            severity=vuln['type'],
            description=vuln['desc'],
            numerical_severity=vuln['mark'],
            mitigated__isnull=True,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            test=test[0]
        )
        if created:
            endpoints_objs = Endpoint.objects.filter(id__in=endpoints_objs)
            finding.endpoints.set(endpoints_objs)
    
    return True

@app.task
def prepare_report(all_scans, type_scan):
        scan_ids = []
        for scan in all_scans:
            scan_id = scan["scan_id"]
            checked_scan = CheckedScan.objects.filter(scan_id=scan_id, checked=True, scan_type=type_scan)
            if checked_scan:
                continue
            scan_ids.append(scan_id)

        for scan_id in scan_ids:
            CheckedScan.objects.update_or_create(scan_id=scan_id, checked=True, scan_type=type_scan)
            gen_json = {
                "export_id": type_scan,
                "source": {
                    "list_type": "scans",
                    "id_list": [scan_id]
                }
            }

            result = get_report.apply_async(args=[gen_json])

@app.task
def get_report(gen_json):
    generate_api = ApiGenerateExport(gen_json)
    json_result = json.loads(generate_api.do())
    report_id = json_result["report_id"]
    
    while True:
        get_api = ApiGetExport(report_id)
        get_json_result = json.loads(get_api.do())
        status = get_json_result["status"]

        if status == "completed":
            download_url = get_json_result.get("download")[0]
            if download_url:
                correct_url = '/'.join(download_url.split("/")[3:])
                url = f"{ACUNETIX_URL}/{correct_url}"

                response = requests.get(url, stream=True, verify=False)
                file_name = download_url.split('/')[-1]
                dir_with_files = "/app/dojo/acunetix/tmp_storage"
                file_path = f"{dir_with_files}/{file_name}"
                if not os.path.exists(file_path):
                    with open(file_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                print("file_path", file_path)
                return file_path
        time.sleep(5)

def schedule_task(period, periodic_in_seconds, type_scan):
    all_scans = get_all_scans()
    if period == "O":
        prepare_report.apply_async(args=(all_scans, type_scan))
    if period == "P":
        schedule, _ = IntervalSchedule.objects.get_or_create(
            every=periodic_in_seconds,
            period=IntervalSchedule.SECONDS
        )

        start_time = datetime.now() + timedelta(seconds=periodic_in_seconds)
        PeriodicTask.objects.update_or_create(
            name=f"Scan Parser {periodic_in_seconds}s",
            defaults = {
            "interval": schedule,
            "task": "dojo.acunetix.another.prepare_report",
            "args": json.dumps([all_scans, type_scan]),
            "enabled": True,
            "start_time": start_time
            }
        )

def update_args_in_periodic_task(task="dojo.acunetix.another.prepare_report"):
    periodic_tasks = PeriodicTask.objects.filter(
        task=task,
        enabled=True,
    )
    for periodic_task in periodic_tasks:
        scans = get_all_scans()
        periodic_task.args = json.dumps(
            [scans, json.loads(periodic_task.args)[1]]
        )
        periodic_task.save()
    logger.info("update args in tasks")

def get_all_target_groups():
    api = ApiGetTargetGroups()
    return do_request(api)

def delete_target_groups_by_ids(group_id_list):
    api = ApiDeleteTargetGroups(group_id_list)
    return do_request(api)

def get_splited_items(request):
    group_ids = request.body.decode('utf-8').split("&")[1:]
    return [item.split('=')[1] for item in group_ids]