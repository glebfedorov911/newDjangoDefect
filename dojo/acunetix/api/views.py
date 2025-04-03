from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema, OpenApiParameter


from dojo.acunetix.acunetix_api.acunetix_exception import AcunetixException
from dojo.acunetix.acunetix_api.acunetix_access import check_acunetix_api
from dojo.acunetix.another import (
    check_has_product, create_target_group, delete_target_groups_by_ids, 
    fill_statistic, fill_statistic_for_files, 
    get_all_scans, get_all_target_groups, get_scans_in_processing,
    post_scan_request, post_target_request, schedule_task, set_target_to_group,
)
from dojo.acunetix.api.serializers import (
    PeriodicTaskSerializer,
    TargetCreateSerializer,
    TargetsCreateSerializer,
    GetReportSerializer,
    TargetGroupsSerializer,
)
from dojo.api_v2.permissions import UserHasDojoGroupPermission
from django_celery_beat.models import PeriodicTask

import logging


logger = logging.getLogger(__name__)

class TargetCreateViewSet(viewsets.ViewSet):

    permission_classes = [IsAuthenticated, UserHasDojoGroupPermission]

    @extend_schema(
        summary="Создать цель и начать сканирование",
        description="""
        description - описание
        criticality - уровень критичность (0 - слабый, 10 - низкий, 20 - средний, 30 -высокий)
        scan_type - тип сканирования (
            11111111-1111-1111-1111-111111111111 - полное сканирование
            11111111-1111-1111-1111-111111111113 - SQL инъекции
            11111111-1111-1111-1111-111111111115 - слабые пароли
        )
        address - url
        type - оставить пустым
        Возвращает ответ о успешности запроса
        """,
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
        request=TargetCreateSerializer
    )
    @check_acunetix_api
    @action(detail=False, methods=['post'], url_path='target-create')
    def create_one_target(self, request):
        try:
            logger.info(f"%s Request to acunetix/targets/create", request.method)
            target_form = TargetCreateSerializer(data=request.data)
            
            if target_form.is_valid():
                cleaned_data = target_form.validated_data
                scan_type = cleaned_data.pop("scan_type")
                address = cleaned_data.get("address")
                
                try:
                    protocol, product = check_has_product(address)
                except Exception:
                    return Response({"error": f"Not found address with address {address}"}, status=status.HTTP_400_BAD_REQUEST)
                
                target = post_target_request(cleaned_data)
                target_id = target.get("target_id")
                
                scan = post_scan_request(target_id, scan_type)
                fill_statistic.apply_async(
                    args=[scan, protocol, product, address]
                )
                
                return Response({"message": "success"})
            else:
                logger.error("Mistakes %s", target_form.errors)
                return Response(target_form.errors, status=status.HTTP_400_BAD_REQUEST)
        except AcunetixException as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
    @extend_schema(
        summary="Создать множество целей и начать сканирование",
        description="""
        description - описание
        criticality - уровень критичность (0 - слабый, 10 - низкий, 20 - средний, 30 -высокий)
        scan_type - тип сканирования (
            11111111-1111-1111-1111-111111111111 - полное сканирование
            11111111-1111-1111-1111-111111111113 - SQL инъекции
            11111111-1111-1111-1111-111111111115 - слабые пароли
        )
        addresses - список url
        type - оставить пустым
        Возвращает ответ о успешности запроса
        """,
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
        request=TargetsCreateSerializer
    )
    @check_acunetix_api
    @action(detail=False, methods=['post'], url_path='targets-create')
    def create_some_targets(self, request):
        try:
            logger.info(f"%s Request to acunetix/targets/create-any", request.method)
            targets_form = TargetsCreateSerializer(data=request.data)

            if targets_form.is_valid():
                cleaned_data = targets_form.data
                addresses = cleaned_data.pop("addresses")
                group_name = cleaned_data.pop("name")
                
                try:
                    target_group = create_target_group(group_name)
                except:
                    return Response({"error": f"Already exist this target"}, status=status.HTTP_400_BAD_REQUEST)
                target_ids = []
                scans = {}
                for url in addresses:
                    target = TargetCreateSerializer(data={
                        "address": url,
                        **cleaned_data
                    })
                    if target.is_valid():
                        target_cleaned_data = target.data
                        scan_type = target_cleaned_data.pop("scan_type")
                        address = target_cleaned_data.get("address")
                        try:
                            protocol, product = check_has_product(address)
                        except ValueError as e:
                            return Response({"error": f"Not found address with address {address}"}, status=status.HTTP_400_BAD_REQUEST)

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

                return Response({"message": "success"})
            else:
                logger.error("Mistakes %s", targets_form.errors)
                return Response(targets_form.errors, status=status.HTTP_400_BAD_REQUEST)
        except AcunetixException as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Получить все активные сканы",
        description="Возвращает все АКТИВНЫЕ сканы",
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
    )
    @check_acunetix_api
    @action(detail=False, methods=['get'], url_path='get-active-scans')
    def get_active_scans(self, request):
        scans = get_scans_in_processing()
        return Response(scans)
    
    
    @extend_schema(
        summary="Получить все сканы",
        description="Возвращает все сканы",
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
    )
    @check_acunetix_api
    @action(detail=False, methods=['get'], url_path='get-scans')
    def get_scans(self, request):
        scans = get_all_scans()
        return Response(scans)
    
    @extend_schema(
        summary="Импортировать отчеты",
        description="""
        type_import = Тип импорта (P - периодичность, O - один раз)
        periodic - Периодичность в секундах
        type_scan - (
            11111111-1111-1111-1111-111111111111 = HTML
            21111111-1111-1111-1111-111111111130 = JSON
            21111111-1111-1111-1111-111111111111 = XML
        )
        Возвращает ответ о успешности старта
        """,
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
        request=GetReportSerializer
    )
    @check_acunetix_api
    @action(detail=False, methods=['post'], url_path='import-reports')
    def import_reports(self, request):
        try:
            form = GetReportSerializer(data=request.data)
            if form.is_valid():
                cleaned_data = form.data
                type_scan = cleaned_data["type_scan"]
                periodic_in_seconds = cleaned_data["periodic"]
                type_import = cleaned_data["type_import"]
                schedule_task(type_import, periodic_in_seconds, type_scan)

                return Response({"message": "success"})
            else:
                return Response({"error": "Invalid form"})
        except AcunetixException as e:
            return Response({"error": str(e)})
        
    @extend_schema(
        summary="Получить таргет группы",
        description="Возвращает все таргет группы",
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ]
    )
    @action(detail=False, methods=['get'], url_path='get-target-groups')
    @check_acunetix_api
    def get_target_groups(self, request):
        groups = get_all_target_groups().get("groups")
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

        return Response(groups_context)
    
    @extend_schema(
        summary="Удалить таргет группы",
        description="Удалить таргет группы, необходимо указать в массив список id групп",
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
        request=TargetGroupsSerializer,
    )
    @action(detail=False, methods=['post'], url_path='delete-target-groups')
    @check_acunetix_api
    def delete_target_groups(self, request):
        serializer = TargetGroupsSerializer(data=request.data)
        if serializer.is_valid():
            group_ids = serializer.data.get("group_ids")
            group_id_list = {"group_id_list": group_ids}
            delete_target_groups_by_ids(group_id_list)
        
            return Response({"message": "success"})
        return Response({"message": str(e)})
        
    @extend_schema(
        summary="Получить все периодические задачи",
        description="Возвращает все периодические задачи",
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
    )
    @action(detail=False, methods=['get'], url_path='periodic-tasks')
    @check_acunetix_api
    def get_periodic_tasks(self, request):
        periodic_tasks = PeriodicTask.objects.all()
        periodic_tasks_context = [
            {
                "id": periodic_task.id,
                "name": periodic_task.name,
                "enabled": periodic_task.enabled,
                "interval": str(periodic_task.interval)
            }
        for periodic_task in periodic_tasks if "Scan Parser" in periodic_task.name]

        return Response(periodic_tasks_context)
    
    @extend_schema(
        summary="Остановить задачи",
        description="Остановить задачи, необходимо указать в массивы задачи, у которых хочется изменить статус",
        parameters=[
            OpenApiParameter(
                name="Acunetix",
            )
        ],
        request=PeriodicTaskSerializer
    )
    @action(detail=False, methods=['post'], url_path='stop-periodic-tasks')
    @check_acunetix_api
    def stop_periodic_tasks(self, request):
        serializer = PeriodicTaskSerializer(data=request.data)
        if serializer.is_valid():
            active_ids = [int(i) for i in serializer.data.get('active', [])]
            inactive_ids = [int(i) for i in serializer.data.get('inactive', [])]
            
            PeriodicTask.objects.filter(id__in=active_ids).update(enabled=True)
            PeriodicTask.objects.filter(id__in=inactive_ids).update(enabled=False)

            return Response({"message": "success"})
        return Response({"error": "invalid form"})