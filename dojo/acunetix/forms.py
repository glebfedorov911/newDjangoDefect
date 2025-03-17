import uuid

from django import forms


class ExcludeHours(forms.Form):
    day_of_week = forms.ChoiceField(
        choices=[
            (1, "Понедельник"), (2, "Вторник"), (3, "Среда"),
            (4, "Четверг"), (5, "Пятница"), (6, "Суббота"), (7, "Воскресенье")
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