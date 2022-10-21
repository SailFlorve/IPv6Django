import pathlib
from abc import abstractmethod
from os import PathLike
from typing import Callable

from IPv6Django.tools.process_executor import ProcessExecutor


class IPv6TaskBase:
    """
    抽象了一个任务的基本流程，包括：
    1. 传入工作路径
    2. 设置完成回调
    3. 执行和停止
    """

    def __init__(self, work_path: str | PathLike[str], origin_file_path: str | PathLike[str] = pathlib.Path()):
        self.work_path: pathlib.Path = pathlib.Path(work_path)
        self.origin_file_path: pathlib.Path = pathlib.Path(origin_file_path)
        self.finished_callback: Callable[[int, ], None] = lambda return_code: None
        self.process_executor = ProcessExecutor()

    def set_finished_callback(self, callback: Callable[[int, ], None]):
        self.finished_callback = callback

    @abstractmethod
    def run(self):
        pass

    def stop(self):
        self.process_executor.terminate()

    def set_cmd_out_callback(self, std_out_callback: Callable[[str, ], None]):
        self.process_executor.stdout_callback = std_out_callback
