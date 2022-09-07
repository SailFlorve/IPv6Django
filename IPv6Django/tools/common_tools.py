import json
import os
import pathlib
import socket
import subprocess
import uuid
import zipfile

from django.http import HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework.views import exception_handler

from IPv6Django import settings
from IPv6Django.bean.beans import BaseBean, Status
from IPv6Django.ipv6_extend.constant import Constant
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

        return CustomResponse(code=response.status_code, msg=msg)

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
        status = Status(Status.SERVER_EXCEPTION, f"服务器异常: {exception}")
        return JsonResponse(status.to_dict(), status=500)


class CommonTools:
    @staticmethod
    def get_ipv6():
        host_ipv6 = []
        ips = socket.getaddrinfo(socket.gethostname(), 80)

        for ip in ips:
            print(ip[4])
            if ip[4][0].find(":") != -1 and not ip[4][0].startswith('fe80'):
                # 2408 中国联通
                # 2409 中国移动
                # 240e 中国电信
                host_ipv6.append(ip[4][0])

        if len(host_ipv6) == 0:
            # return ""
            if settings.DEBUG:
                return '2001:da8:100e:5000::1:59af'
            else:
                return '2001:da8:100e:5000::1:59af'
        else:
            return host_ipv6[0]

    @staticmethod
    def line_count(file_path):
        try:
            output = subprocess.check_output(['wc', '-l', file_path])
            return int(output.split()[0])
        except Exception as e:
            print(e)
            return 0

    @staticmethod
    def get_uuid() -> str:
        return str(uuid.uuid1())

    @staticmethod
    def require_not_none(*values) -> bool:
        for value in values:
            if value is None:
                return False
        return True

    @staticmethod
    def require_int(value: str):
        try:
            info = int(value)
            return True, info
        except ValueError:
            return False

    @staticmethod
    def get_http_response(obj: BaseBean):
        return HttpResponse(obj.to_json(), content_type="application/json,charset=utf-8")

    @staticmethod
    def get_work_path(task_id: str) -> pathlib.Path:
        return pathlib.Path(Constant.RESULT_DIR_PATH) / task_id

    @staticmethod
    def get_work_result_path_by_task_id(task_id: str) -> pathlib.Path:
        return CommonTools.get_work_path(task_id) / Constant.RESULT_DIR_PATH

    @staticmethod
    def get_work_result_path_by_work_path(work_path: pathlib.Path) -> pathlib.Path:
        return work_path / Constant.RESULT_DIR_PATH

    @staticmethod
    def get_target_addr_examples_json(task_id: str) -> str:
        all_count = 100
        current_count = 0
        result = []
        target_path = CommonTools.get_work_path(task_id) / Constant.TARGET_DIR_PATH
        for file in target_path.glob("*"):
            with open(file, 'r') as f:
                for line in f:
                    result.append({"addr": line.strip()})
                    current_count += 1
                    if current_count >= all_count:
                        break
        return json.dumps(result)


class Logger:
    @staticmethod
    def get_log_path(task_id: str = None, path: str | pathlib.Path = None) -> pathlib.Path:
        if path is None:
            path = CommonTools.get_work_result_path_by_task_id(task_id)
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
        else:
            path = CommonTools.get_work_result_path_by_work_path(path)
        path = path / Constant.LOG_FILE_NAME
        return path

    @staticmethod
    def log_to_file(content: str, task_id: str = None, path: str | pathlib.Path = None):
        """
        将日志打印到控制台并写入文件
        :param content:
        :param task_id:
        :param path: 工作路径，默认应是result/task_id
        """

        path = Logger.get_log_path(task_id, path)
        print(content)
        print(content, file=open(path, "a"))


class ZipTool:
    def __init__(self):
        self.dir_list = []

    def add_dir(self, dir_path: str):
        self.dir_list.append(dir_path)
        return self

    def zip(self, file_name):
        zipf = zipfile.ZipFile(file_name, 'w', zipfile.ZIP_DEFLATED)
        for d in self.dir_list:
            self.__zip_dir_internal(d, zipf)
        zipf.close()

    def __zip_dir_internal(self, path, zip_h):
        for root, dirs, files in os.walk(path):
            for file in files:
                zip_h.write(os.path.join(root, file),
                            os.path.relpath(os.path.join(root, file),
                                            os.path.join(path, '..')))


if __name__ == '__main__':
    print(CommonTools.get_ipv6())
