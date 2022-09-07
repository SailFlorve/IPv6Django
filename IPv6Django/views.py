from django.http import HttpResponse
from django.views.decorators.http import require_POST

from IPv6Django.tools.common_tools import CommonTools
from IPv6Django.tools.singleton import Singleton


@require_POST
def upload_ipv6_generate(request):
    f = request.FILES.get('ipv6_file')
    budget = request.POST.get('budget')
    probe = request.POST.get('probe')
    band_width = request.POST.get('band_width')
    port = request.POST.get('port')

    not_none = CommonTools.require_not_none(budget, probe, band_width, port)
    if not not_none:
        return HttpResponse("参数不能为空!")

    ipv6_manager = Singleton.get_ipv6_controller()
    ipv6_upload_status = ipv6_manager.start_ipv6_generate(f, budget, probe, band_width, port)

    return CommonTools.get_http_response(ipv6_upload_status)


@require_POST
def get_task_ids(request):
    ipv6_manager = Singleton.get_ipv6_controller()
    return CommonTools.get_http_response(ipv6_manager.get_tasks())


@require_POST
def get_task_state(request):
    task_id = request.POST.get('task_id')
    check = CommonTools.require_not_none(task_id)
    if not check:
        return HttpResponse("参数不能为空!")

    ipv6_manager = Singleton.get_ipv6_controller()
    return CommonTools.get_http_response(ipv6_manager.get_task_state(task_id))


@require_POST
def get_task_result(request):
    task_id = request.POST.get('task_id')
    download_type = request.POST.get('download_type')
    check = CommonTools.require_not_none(task_id, download_type)
    if not check:
        return HttpResponse("参数不能为空!")

    ipv6_manager = Singleton.get_ipv6_controller()
    return ipv6_manager.get_task_result(task_id, download_type)


@require_POST
def terminate_task(request):
    task_id = request.POST.get('task_id')
    check = CommonTools.require_not_none(task_id)
    if not check:
        return HttpResponse("参数不能为空!")

    ipv6_manager = Singleton.get_ipv6_controller()
    return CommonTools.get_http_response(ipv6_manager.stop_task(task_id))


@require_POST
def vulnerability_scan(request):
    f = request.FILES.get('ipv6_file')
    params = request.POST.get('params', '')

    ipv6_manager = Singleton.get_ipv6_controller()
    return CommonTools.get_http_response(ipv6_manager.start_ipv6_vulnerability_scan(f, params))


@require_POST
def get_log(request):
    task_id = request.POST.get('task_id')
    ipv6_manager = Singleton.get_ipv6_controller()
    return CommonTools.get_http_response(ipv6_manager.get_log(task_id))
