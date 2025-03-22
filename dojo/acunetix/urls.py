from django.urls import re_path

from dojo.acunetix import views

urlpatterns = [
    re_path(r'acunetix/targets/create-any-targets', views.create_targets_and_start_scan, name='create_targets_and_start_scan'),
    re_path(r'acunetix/targets/create-target', views.create_target_and_start_scan, name='create_target_and_start_scan'),
]
