from rest_framework import serializers

import uuid
import ipaddress

from dojo.models import *


class AcunetixServerSerializer(serializers.Serializer):
    server = serializers.IntegerField(required=False)

class AcunetixAddServerSerializer(serializers.Serializer):
    
    
    class Meta:
        model = AcunetixServers
        fields = "__all__"

class AcunetixDeleteSerializer(serializers.Serializer):
    ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False
    )

class ExcludeHoursSerializer(serializers.Serializer):


    day_of_week = serializers.ChoiceField(
        choices=[
            (1, "Воскресенье"), (2, "Понедельник"), (3, "Вторник"), (4, "Среда"),
            (5, "Четверг"), (6, "Пятница"), (7, "Суббота")
        ]
    )

    HOURS = [(str(i), f"{i}:00") for i in range(1, 25)]

    start_time = serializers.ChoiceField(choices=HOURS)
    finish_time = serializers.ChoiceField(choices=HOURS)

class ExcludeHoursFormSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    excluded_hours_id = serializers.UUIDField(default=uuid.uuid4)
    time_offset = serializers.IntegerField(default=0)
    exclude_hours = ExcludeHoursSerializer(many=True)

class TargetCreateMixinSerializer(serializers.Serializer):
    
    
    LOW = 0
    MEDIUM = 10
    HIGH = 20
    CRITICAL = 30

    CRITICALITY_CHOICES = (
        (LOW, "Самая важная цель"),
        (MEDIUM, "Важная цель"),
        (HIGH, "Средняя цель"),
        (CRITICAL, "Низкая цель"),
    )

    FULL_SCAN = "11111111-1111-1111-1111-111111111111"
    HIGH_RISK_VULNERABILITIES = "11111111-1111-1111-1111-111111111112"
    CROSS_SITE_SCRIPTING_VULNERABILITIES = "11111111-1111-1111-1111-111111111116"
    SQL_INJECTION_VULNERABILITIES = "11111111-1111-1111-1111-111111111113"
    WEAK_PASSWORDS = "11111111-1111-1111-1111-111111111115"
    CRAWL_ONLY = "11111111-1111-1111-1111-111111111117"

    SCAN_CHOICES = (
        (FULL_SCAN, "Полное сканирование"),
        (HIGH_RISK_VULNERABILITIES, "Высокие риски уязвимостей"),
        (CROSS_SITE_SCRIPTING_VULNERABILITIES, "Уязвимости Cross-site Scripting (XSS)"),
        (SQL_INJECTION_VULNERABILITIES, "Уязвимости SQL-инъекций"),
        (WEAK_PASSWORDS, "Слабые пароли"),
        (CRAWL_ONLY, "Только сканирование (без проверки)"),
    )

    description = serializers.CharField(max_length=255, required=False)
    criticality = serializers.ChoiceField(choices=CRITICALITY_CHOICES)
    scan_type = serializers.ChoiceField(choices=SCAN_CHOICES)

    @staticmethod
    def is_valid_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

class TargetCreateSerializer(TargetCreateMixinSerializer, AcunetixServerSerializer):


    DEFAULT = "default"
    NETWORK = "network"

    address = serializers.CharField(max_length=255)
    type = serializers.CharField(max_length=7, write_only=True, required=False)
    
    def clean(self):
        cleaned_data = super().clean()
        address = cleaned_data.get("address")

        type_checking = self.NETWORK if self.is_valid_ip(address) else self.DEFAULT
        cleaned_data["type"] = type_checking

        return cleaned_data

class TargetsCreateSerializer(TargetCreateMixinSerializer, AcunetixServerSerializer):


    name = serializers.CharField(
    )
    addresses = serializers.ListField(
        child=serializers.CharField(max_length=100),
        allow_empty=False
    )

class GetReportSerializer(AcunetixServerSerializer):
    DEV = "11111111-1111-1111-1111-111111111111"
    JSON = "21111111-1111-1111-1111-111111111130"
    XML = "21111111-1111-1111-1111-111111111111"

    TYPE_SCAN = (
        (DEV, "HTML"),
        (JSON, "JSON"),
        (XML, "XML"),
    )
    
    ONCE = "O"
    PERIOD = "P"

    TYPE_IMPORT = (
        (PERIOD, "Постоянно"),
        (ONCE, "Единовременно"),
    )

    type_import = serializers.ChoiceField(
        label="Периодичность", choices=TYPE_IMPORT, 
    )
    periodic = serializers.IntegerField(
        label="Периодичность запуска импорта (в секундах)", required=False,
    )
    type_scan = serializers.ChoiceField(label="Формат файла", choices=TYPE_SCAN)

class TargetGroupsSerializer(AcunetixServerSerializer):


    group_ids = serializers.ListField(
        child=serializers.CharField(max_length=50)
    )

class PeriodicTaskSerializer(serializers.Serializer):


    active = serializers.ListField(
        child=serializers.IntegerField()
    )
    inactive = serializers.ListField(
        child=serializers.IntegerField()
    )