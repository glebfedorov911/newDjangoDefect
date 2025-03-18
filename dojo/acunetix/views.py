from dojo.acunetix.acunetix_api.acunetix_access import check_acunetix_api
from dojo.acunetix.forms import ExcludeHoursForm, ExcludeHoursFormSet

from django.http import HttpResponse
from django.shortcuts import render


@check_acunetix_api
def create_exclude_hour_form(request):
    if request.method == "POST":
        main_form = ExcludeHoursForm(request.POST)
        exclude_hours_form_set = ExcludeHoursFormSet(request.POST)

        if main_form.is_valid() and exclude_hours_form_set.is_valid():
            print(main_form.cleaned_data)
            print(exclude_hours_form_set.cleaned_data)
            print(main_form.cleaned_data.get("name"))
            print(exclude_hours_form_set.cleaned_data[0].get("day_of_week"))

    
    elif request.method == "GET":
        main_form = ExcludeHoursForm()
        exclude_hours_form_set = ExcludeHoursFormSet()

    return render(
        request,
        "dojo/acunetix_create_exclude_hours.html",
        {"main_form": main_form, "exclude_hours_form_set": exclude_hours_form_set}
    )