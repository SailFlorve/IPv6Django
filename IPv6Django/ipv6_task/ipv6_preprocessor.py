import time
from os import PathLike
from typing import Callable

from IPv6Django.constant.constant import Constant
from IPv6Django.ipv6_task.ipv6_task_base import IPv6TaskBase
from IPv6Django.tools.common_tools import CommonTools
from IPv6Django.tools.logger import Logger


class Tree6Preprocessor(IPv6TaskBase):
    def __init__(self, origin_file_path_str: str | PathLike[str], work_path_str: str | PathLike[str]):
        super(Tree6Preprocessor, self).__init__(work_path_str, origin_file_path_str)
        self.tree_path = (self.work_path / Constant.TREE_DIR_PATH)
        self.seeds_path = (self.work_path / Constant.SEEDS_PATH)
        self.seeds_path.parent.mkdir(parents=True, exist_ok=True)

    def set_finished_callback(self, callback: Callable[[int, int], None]):
        self.finished_callback = callback

    def run(self) -> None:
        self.__preprocess()

    def stop(self):
        self.process_executor.terminate()

    def __preprocess(self):
        self.__transform()

    def __transform(self):
        cmd = f"{Constant.LIB_TREE_PATH} -T -in-std {str(self.origin_file_path)} -out-b4 {str(self.seeds_path)}"
        Logger.log_to_file(cmd, path=self.work_path)
        self.process_executor.execute(cmd, finished_callback=self.__wait_file)
        # 此处返回

    def __wait_file(self, return_code):
        Logger.log_to_file(f"Transform finished, return code {return_code}", path=self.work_path)

        if return_code != 0:
            self.finished_callback(return_code, 0)
            return

        times = 0

        # 等待文件生成
        path = self.seeds_path
        Logger.log_to_file("Wait for seeds_hex", path=self.work_path)

        time_interval = 0.1
        while not path.exists():
            time.sleep(time_interval)
            times += 1
            if times % 600 == 0:
                Logger.log_to_file(f"Wait for seeds_hex for {times * time_interval} seconds", path=self.work_path)

            if times > 6000:
                raise Exception("Wait for seeds_hex timeout")

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
            if self.finished_callback is not None:
                self.finished_callback(return_code, line_count)

        cmd = f"{Constant.LIB_TREE_PATH} -G -in-b4 {str(self.seeds_path)} -out-tree {str(self.tree_path)}"
        Logger.log_to_file(cmd, path=self.work_path)
        ret, _, _ = self.process_executor.execute(cmd)
        __on_finished(ret)
