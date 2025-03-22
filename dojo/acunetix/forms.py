import uuid
import ipaddress

from django import forms
from django.core.validators import FileExtensionValidator


class ExcludeHours(forms.Form):

    
    day_of_week = forms.ChoiceField(
        choices=[
            (1, "Воскресенье"), (2, "Понедельник"), (3, "Вторник"), (4, "Среда"),
            (5, "Четверг"), (6, "Пятница"), (7, "Суббота")
        ],
        label="День недели"
    )

    HOURS = [(str(i), f"{i}:00") for i in range(1, 25)]

    start_time = forms.ChoiceField(label="Время начала", choices=HOURS)
    finish_time = forms.ChoiceField(label="Время окончания", choices=HOURS)

ExcludeHoursFormSet = forms.formset_factory(ExcludeHours, extra=1)

class ExcludeHoursForm(forms.Form):


    name = forms.CharField(label="название", max_length=100)
    excluded_hours_id = forms.UUIDField(initial=uuid.uuid4, 
                                        widget=forms.HiddenInput(),
                                        required=False)
    time_offset = forms.CharField(label="смещение по времени в минутах", 
                                  initial=0)
    
class TargetCreateMixinForm(forms.Form):


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

    description = forms.CharField(label="Описание", max_length=255, required=False)
    criticality = forms.ChoiceField(label="Критичность", choices=CRITICALITY_CHOICES)
    scan_type = forms.ChoiceField(label="Тип сканирования", choices=SCAN_CHOICES)
    
    @staticmethod
    def is_valid_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

class TargetCreateForm(TargetCreateMixinForm):


    DEFAULT = "default"
    NETWORK = "network"

    address = forms.CharField(label="URL-адрес", max_length=255)
    type = forms.CharField(label="Тип", max_length=7, widget=forms.HiddenInput(), required=False)
    
    def clean(self):
        cleaned_data = super().clean()
        address = cleaned_data.get("address")

        type_checking = self.NETWORK if self.is_valid_ip(address) else self.DEFAULT
        cleaned_data["type"] = type_checking

        return cleaned_data

class TargetsCreateForm(TargetCreateMixinForm):


    addresses = forms.FileField(
        validators=[FileExtensionValidator(allowed_extensions=["txt"])],
        label="Файл (txt, URL'ы через точку с запятой)"
    )