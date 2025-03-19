from dojo.acunetix.acunetix_api.acunetix_access import check_acunetix_api
from dojo.acunetix.acunetix_api.acunetix_exclude_hours import ExcludeHoursProfile
from dojo.acunetix.forms import ExcludeHoursForm, ExcludeHoursFormSet
from dojo.acunetix.acunetix_api.acunetix_request_exclude_hours_create import ApiCreateExcludeHours

from django.http import HttpResponse
from django.shortcuts import render


@check_acunetix_api
def create_exclude_hour_form(request):
    if request.method == "POST":
        try:
            main_form = ExcludeHoursForm(request.POST)
            exclude_hours_form_set = ExcludeHoursFormSet(request.POST)

            if main_form.is_valid() and exclude_hours_form_set.is_valid():
                exclude_hour_profile = ExcludeHoursProfile(
                    main_form.cleaned_data.get("name"),
                    main_form.cleaned_data.get("excluded_hours_id"),
                    int(main_form.cleaned_data.get("time_offset")),
                    [{key: int(value) for key, value in l.items()} 
                    for l in exclude_hours_form_set.cleaned_data]
                )

                api = ApiCreateExcludeHours(exclude_hour_profile)
                print(api.do())
                return HttpResponse("Good")
        except Exception as e:
            return HttpResponse(str(e))
    
    elif request.method == "GET":
        main_form = ExcludeHoursForm()
        exclude_hours_form_set = ExcludeHoursFormSet()

    return render(
        request,
        "dojo/acunetix_create_exclude_hours.html",
        {"main_form": main_form, "exclude_hours_form_set": exclude_hours_form_set}
    )