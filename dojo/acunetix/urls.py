from django.urls import re_path

from dojo.acunetix import views

urlpatterns = [
    re_path(r'acunetix/targets/create-any', views.create_targets_and_start_scan, name='create_targets_and_start_scan'),
    re_path(r'acunetix/targets/create', views.create_target_and_start_scan, name='create_target_and_start_scan'),
    re_path(r'acunetix/scans/active', views.get_active_scans, name='active_scans'),
]
