import json
import os
import pathlib
import random
import shutil
import socket
import subprocess
import time
import uuid
import zipfile

from django.http import HttpResponse

from IPv6Django.bean.beans import BaseBean
from IPv6Django.constant.constant import Constant


class CommonTools:
    @staticmethod
    def get_ipv6():
        try:
            return CommonTools.get_ipv6_cmd()
        except subprocess.CalledProcessError:
            return CommonTools.get_ipv6_socket()

    @staticmethod
    def get_ipv6_cmd():
        ipv6 = subprocess.check_output(
            r"ip -6 addr | grep inet6 | awk -F '[ \t]+|/' '{print $3}' | grep -v ^::1 | grep -v ^fe80", shell=True,
            encoding="utf-8")
        return ipv6.split("\n")[0]

    @staticmethod
    def get_ipv6_socket():
        host_ipv6 = []
        ips = socket.getaddrinfo(socket.gethostname(), 80)

        for ip in ips:
            print(ip[4])
            if ip[4][0].find(":") != -1:
                # 2408 中国联通
                # 2409 中国移动
                # 240e 中国电信
                host_ipv6.append(ip[4][0])

        if len(host_ipv6) == 0:
            return ""
            # if settings.DEBUG:
            #     return '2001:da8:100e:5000::1:59af'
            # else:
            #     return '2001:da8:100e:5000::1:59af'
        else:
            all_local_ipv6 = True
            global_ipv6: str = ""
            for ipv6 in host_ipv6:
                if not ipv6.startswith("fe80"):
                    global_ipv6 = ipv6
                    all_local_ipv6 = False
            return host_ipv6[0] if all_local_ipv6 else global_ipv6

    @staticmethod
    def line_count(file_path):
        try:
            output = subprocess.check_output(['wc', '-l', file_path])
            return int(output.split()[0])
        except Exception as e:
            print(e)
            return 0

    @staticmethod
    def get_dir_size(dir_path: str) -> str:
        res_list = os.popen(f'du {dir_path} -h --max-depth=0')

        res_list = [x.split('\t') for x in res_list]

        return res_list[0][0]

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
        """
        result/task_id
        """
        return pathlib.Path(Constant.RESULT_DIR_PATH) / task_id

    @staticmethod
    def get_work_result_path_by_task_id(task_id: str) -> pathlib.Path:
        """
        result/task_id/result
        """
        return CommonTools.get_work_path(task_id) / Constant.RESULT_DIR_PATH

    @staticmethod
    def clear_task_cache(task_id: str):
        """
        清除任务缓存
        """
        work_path = CommonTools.get_work_path(task_id)
        if not work_path.exists():
            return

        cache_path: list[pathlib.Path] = [
            work_path / Constant.TARGET_TMP_PATH,
            work_path / Constant.RESULT_TMP_PATH,
            # work_path / Constant.SEEDS_NAME,
            work_path / Constant.TREE_DIR_PATH
        ]
        for path in cache_path:
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink()

    @staticmethod
    def delete_task_dir(task_id: str):
        upload_path = pathlib.Path(Constant.UPLOAD_DIR_PATH) / task_id
        shutil.rmtree(upload_path, ignore_errors=True)
        work_path: pathlib.Path = CommonTools.get_work_path(task_id)
        shutil.rmtree(work_path, ignore_errors=True)

    @staticmethod
    def get_work_result_path_by_work_path(work_path: pathlib.Path) -> pathlib.Path:
        """
        result/task_id/result
        :param work_path: result/task_id
        """

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

    @staticmethod
    def merge_all_file(targets_dir_path: pathlib.Path, target_file_path: pathlib.Path, delete_source: bool = True):
        """
        合并所有文件
        :param targets_dir_path: 目标文件夹
        :param target_file_path: 目标文件
        :param delete_source: 是否删除源文件
        """
        buffer_size = 1024 * 1024 * 5  # 5M

        with open(target_file_path, 'w+') as f:
            for file in sorted(targets_dir_path.glob("*")):
                if file == target_file_path:
                    continue

                with open(file, 'r') as f1:
                    while True:
                        data = f1.read(buffer_size)
                        if data:
                            f.write(data)
                        else:
                            break

        if delete_source:
            for file in targets_dir_path.glob("*"):
                if file != target_file_path:
                    file.unlink()

    @staticmethod
    def get_format_time(fmt: str = '%Y%m%d%H%M%S') -> str:
        """
        获取格式化时间
        @param fmt: %Y %m %d %H %M %S
        @return: 格式化时间str
        """
        return time.strftime(fmt, time.localtime())


class RandomTool:
    @staticmethod
    def choose_randomly(data_list: list, count: int = 1):
        """
        随机选择
        :param data_list: 列表
        :param count: 个数
        :return:
        """
        if len(data_list) <= count:
            return data_list
        elif count == 1:
            return random.sample(data_list, count)[0]
        else:
            return random.sample(data_list, count)

    @staticmethod
    def generate_random_num_seq(start: int, end: int, count: int) -> str:
        return ''.join(map(str, random.sample(range(start, end), count)))

    @staticmethod
    def rand_int(start: int, end: int) -> int:
        return random.randint(start, end)


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
    print(CommonTools.get_format_time("%Y%m.%d%H%M%S")[2:])
