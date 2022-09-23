from dataclasses import dataclass
from functools import wraps

from rest_framework.request import Request

from IPv6Django.bean.beans import Status
from IPv6Django.tools.custom_response import CustomResponse


@dataclass
class CheckType:
    name: str
    type: str
    values: list | None = None  # 可选值


def request_verify(require_params: list[str] | None = None,
                   require_form_datas: list[str] | None = None,
                   check_types: list[CheckType] | None = None):
    """
    用于检查前端传入数据的装饰器
    其中check_types和check_values的key必须是require_params
    """

    def decorator(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            request = self if isinstance(self, Request) else args[0]
            if request is None or not isinstance(request, Request):
                return func(self, *args, **kwargs)

            param_list = [] if require_params is None else require_params
            form_data_list = [] if require_form_datas is None else require_form_datas
            check_type_list = [] if check_types is None else check_types

            for param in param_list:
                if param not in request.query_params \
                        or request.query_params[param] is None \
                        or request.query_params[param] == '':
                    return CustomResponse(Status.LACK_PARAM.with_extra(f"缺少参数: {param}"))

            for form_data in form_data_list:
                if form_data not in request.data \
                        or request.data[form_data] is None \
                        or request.data[form_data] == '':
                    return CustomResponse(Status.LACK_PARAM.with_extra(f"缺少参数: {form_data}"))

            for check_type in check_type_list:
                if check_type.name not in request.query_params:
                    continue

                if check_type.type == 'int':
                    try:
                        int(request.query_params[check_type.name])
                    except ValueError:
                        return CustomResponse(Status.PARAM_ERROR.with_extra(f"参数 {check_type.name} 不是整数"))

                    if check_type.values is not None \
                            and int(request.query_params[check_type.name]) not in check_type.values:
                        return CustomResponse(Status.PARAM_ERROR.with_extra(f"参数 {check_type.name} 不在可选范围内"))

                elif check_type.type == 'float':
                    try:
                        float(request.query_params[check_type.name])
                    except ValueError:
                        return CustomResponse(Status.PARAM_ERROR.with_extra(f"参数 {check_type.name} 不是浮点数"))
                    if check_type.values is not None \
                            and float(request.query_params[check_type.name]) not in check_type.values:
                        return CustomResponse(Status.PARAM_ERROR.with_extra(f"参数 {check_type.name} 不在可选范围内"))

                elif check_type.type == 'bool':
                    if request.query_params[check_type.name] == 'true':
                        pass
                    elif request.query_params[check_type.name] == 'false':
                        pass
                    else:
                        return CustomResponse(Status.PARAM_ERROR.with_extra(f"参数 {check_type.name} 不是布尔值"))

            return func(self, *args, **kwargs)

        return inner

    return decorator
