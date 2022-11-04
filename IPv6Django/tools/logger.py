import pathlib
import time

from IPv6Django.constant.constant import Constant
from IPv6Django.tools.common_tools import CommonTools


class Logger:
    @staticmethod
    def get_log_path(task_id: str = None, path: str | pathlib.Path = None) -> pathlib.Path:
        if path is None:
            path = CommonTools.get_work_result_path_by_task_id(task_id)
        else:
            path = CommonTools.get_work_result_path_by_work_path(path)

        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)

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

        if task_id is None and path is None:
            raise Exception("task_id和path不能同时为空")

        path = Logger.get_log_path(task_id, path)
        content = time.strftime("[%Y/%m/%d %H:%M:%S]", time.localtime()) + " " + content
        print(content)
        print(content, file=open(path, "a"))
