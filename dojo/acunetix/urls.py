from django.urls import re_path

from dojo.acunetix import views

urlpatterns = [
    re_path(r'acunetix/exclude-hours', views.create_exclude_hour_form, name='exclude_hours'),
]
