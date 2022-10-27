from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework.views import exception_handler

from IPv6Django.bean.beans import Status
from IPv6Django.tools.custom_response import CustomResponse


def globe_exception_handler(exc, context):
    response = exception_handler(exc, context)
    request = context['request']

    if response is not None:
        if isinstance(response.data, list):
            msg = '; '.join(response.data)
        elif isinstance(response.data, str):
            msg = response.data
        else:
            msg = '出现错误'

        return CustomResponse(Status(response.status_code, msg))

    return response


class ExceptionGlobeMiddleware(MiddlewareMixin):
    """
        Below is the global exception handler of django
    """

    def process_exception(self, request, exception):
        print(type(exception))
        # 直接抛出 django admin 的异常
        if str(request.path).startswith('/admin/'):
            return None

        print(exception)

        # 捕获其他异常，直接返回 500
        status = Status.SERVER_EXCEPTION.with_extra(f"服务器异常: {exception}")
        return JsonResponse(status.to_dict(), status=500)
