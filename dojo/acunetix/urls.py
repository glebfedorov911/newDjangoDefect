from django.urls import re_path

from dojo.acunetix import views

urlpatterns = [
    re_path(r'indepo/targets/create-any', views.create_targets_and_start_scan, name='create_targets_and_start_scan'),
    re_path(r'indepo/targets/create', views.create_target_and_start_scan, name='create_target_and_start_scan'),
    re_path(r'indepo/scans/active', views.get_active_scans, name='active_scans'),
    re_path(r'indepo/scans', views.get_scans, name='scans'),
    re_path(r'indepo/reports/import-now', views.import_reports, name='import_reports'),
    re_path(r'indepo/targets/groups', views.target_groups, name='target_groups'),
    re_path(r'indepo/reports/periodic-tasks', views.periodic_task, name='periodic_task'),
]

