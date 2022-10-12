import pathlib
import time
from abc import abstractmethod
from os import PathLike
from typing import Callable

from IPv6Django.constant.constant import Constant
from IPv6Django.tools.common_tools import CommonTools, Logger
from IPv6Django.tools.process_executor import ProcessExecutor


class IPv6Preprocessor:
    """
    IPv6地址预处理和相关数据结构生成算法
    """

    def __init__(self, origin_file_path_str: str | PathLike[str], work_path_str: str | PathLike[str]):
        super(IPv6Preprocessor, self).__init__()
        self.processExecutor = ProcessExecutor()
        self.origin_file_path = pathlib.Path(origin_file_path_str)
        self.work_path = pathlib.Path(work_path_str)

    @abstractmethod
    def preprocess(self):
        pass


class Tree6Preprocessor(IPv6Preprocessor):
    def __init__(self, origin_file_path_str: str | PathLike[str], work_path_str: str | PathLike[str]):
        super(Tree6Preprocessor, self).__init__(origin_file_path_str, work_path_str)

        self.tree_path = (self.work_path / Constant.TREE_DIR_PATH)
        self.seeds_path = (self.work_path / Constant.SEEDS_PATH)
        self.callback: Callable[[int, int], None] | None = None  # return code, line count

        self.seeds_path.parent.mkdir(parents=True, exist_ok=True)

    def set_finished_callback(self, callback: Callable[[int, int], None]):
        self.callback = callback

    def run(self) -> None:
        self.preprocess()

    def preprocess(self):
        self.__transform()

    def __transform(self):
        cmd = f"{Constant.LIB_TREE_PATH} -T -in-std {str(self.origin_file_path)} -out-b4 {str(self.seeds_path)}"
        Logger.log_to_file(cmd, path=self.work_path)
        self.processExecutor.execute(
            cmd,
            finished_callback=self.__wait_file)

    def __wait_file(self, return_code):
        Logger.log_to_file(f"transform finished, return code {return_code}", path=self.work_path)

        if return_code != 0:
            self.callback(return_code, 0)
            return

        times = 0

        # 等待文件生成
        path = self.seeds_path
        Logger.log_to_file("wait for seeds_hex", path=self.work_path)

        time_interval = 0.1
        while not path.exists():
            time.sleep(time_interval)
            times += 1
            if times % 600 == 0:
                Logger.log_to_file(f"wait for seeds_hex for {times * time_interval} seconds", path=self.work_path)

            if times > 6000:
                raise Exception("wait for seeds_hex timeout")

        line_count = CommonTools.line_count(self.seeds_path)
        last_line_count = line_count

        # 等待文件完全写入，即行数不再变化
        while True:
            Logger.log_to_file(f"wait for line count, last: {last_line_count}", path=self.work_path)
            time.sleep(time_interval)
            line_count = CommonTools.line_count(self.seeds_path)
            if last_line_count == line_count:
                break
            else:
                last_line_count = line_count

        # 生成6Tree相关数据结构
        self.__generate_tree()

    def __generate_tree(self):
        def __on_finished(return_code):
            line_count = CommonTools.line_count(self.seeds_path)
            if self.callback is not None:
                self.callback(return_code, line_count)

        cmd = f"{Constant.LIB_TREE_PATH} -G -in-b4 {str(self.seeds_path)} -out-tree {str(self.tree_path)}"
        Logger.log_to_file(cmd, path=self.work_path)
        self.processExecutor.execute(
            cmd,
            finished_callback=__on_finished)
