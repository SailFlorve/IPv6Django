import pathlib
import time
from abc import abstractmethod
from os import PathLike
from typing import Callable

from IPv6Django.ipv6_extend.constant import Constant
from IPv6Django.tools.common_tools import CommonTools, Logger
from IPv6Django.tools.process_executor import ProcessExecutor


class IPv6Preprocessor:
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
        self.seeds_path = (self.work_path / Constant.SEEDS_NAME)
        self.callback: Callable[[int, int], None] | None = None  # return code, line count

    def set_finished_callback(self, callback: Callable[[int, int], None]):
        self.callback = callback

    def run(self) -> None:
        self.preprocess()

    def __wait_file(self, return_code):
        Logger.log_to_file(f"transform finished, return code {return_code}", path=self.work_path)

        if return_code != 0:
            self.callback(return_code, 0)
            return

        times = 0

        # 等待完全生成
        path = self.seeds_path
        while not path.exists():
            Logger.log_to_file("wait for seeds_hex", path=self.work_path)
            time.sleep(0.1)
            times += 1
            # if times > 50:
            #     return

        line_count = CommonTools.line_count(self.seeds_path)
        last_line_count = line_count

        # 等待文件完全写入
        while True:
            Logger.log_to_file(f"wait for line count, last: {last_line_count}", path=self.work_path)
            time.sleep(0.1)
            line_count = CommonTools.line_count(self.seeds_path)
            if last_line_count == line_count:
                break
            else:
                last_line_count = line_count

        self.__generate_tree()

    def preprocess(self):
        self.__transform()

    def __transform(self):
        cmd = f"{Constant.LIB_TREE_PATH} -T -in-std {str(self.origin_file_path)} -out-b4 {str(self.seeds_path)}"
        Logger.log_to_file(cmd, path=self.work_path)
        self.processExecutor.execute(
            cmd,
            finished_callback=self.__wait_file)

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
