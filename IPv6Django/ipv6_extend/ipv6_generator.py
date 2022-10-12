import pathlib
from abc import abstractmethod
from os import PathLike

from IPv6Django.constant.constant import Constant
from IPv6Django.tools.common_tools import CommonTools, Logger
from IPv6Django.tools.process_executor import ProcessExecutor


class IPv6Generator:
    """
    IPv6地址扩展和探测算法
    """

    def __init__(self, work_path_str: str | PathLike[str]):
        self.processExecutor = ProcessExecutor()
        self.work_path = pathlib.Path(work_path_str)

    @abstractmethod
    def generate(self):
        pass


class Tree6Generator(IPv6Generator):
    def __init__(self, ipv6: str, work_path_str: str | PathLike[str]):
        super(Tree6Generator, self).__init__(work_path_str)
        self.search_params = None
        self.scanner_params = None
        self.tree_path = (self.work_path / Constant.TREE_DIR_PATH)
        self.ipv6 = ipv6

        self.callback = None

    def set_finished_callback(self, callback):
        self.callback = callback

    def set_params(self, budget: int, probe: str, band_width: str, port: str = ""):
        use_port: bool = (probe != "icmp6_echoscan")

        self.search_params = f'''budget : {budget}
step_budget : {int(budget) / 5}
adet_ptimes : 5
adet_tsscale_thd : 1024
adet_aad_thd : 0.95
adet_crip : 1048576'''

        self.scanner_params = f"""app_name : zmap
ins_num : {8 if use_port else 7}
--probe-module={probe}
--ipv6-target-file={str(self.work_path / Constant.TARGET_TMP_PATH)}
--output-file={str(self.work_path / Constant.RESULT_TMP_PATH)}
--ipv6-source-ip={self.ipv6}
--bandwidth={band_width}
--cooldown-time=4
--verbosity=3"""

        if use_port:
            self.scanner_params += f"\n--target-port={port}"

        tree_scanner_path = self.tree_path / "scanner_parameters"
        tree_scanner_path.write_text(self.scanner_params)

        tree_search_path = self.tree_path / "search_parameters"
        tree_search_path.write_text(self.search_params)

    def generate(self):
        def __on_finish(result):
            Logger.log_to_file(f"Generate return code: {result}", path=self.work_path)
            if self.callback is not None:
                self.callback(result)

        Logger.log_to_file(f"Params:\n{self.scanner_params}\n{self.search_params}", path=self.work_path)

        # resultPath = pathlib.Path(f"{Constant.RESULT_DIR_PATH}")
        # shutil.rmtree(resultPath, ignore_errors=True)
        # resultPath = pathlib.Path(f"{Constant.TARGET_TMP_PATH}")
        # resultPath.unlink(missing_ok=True)
        # resultPath = pathlib.Path(f"{Constant.RESULT_TMP_PATH}")
        # resultPath.unlink(missing_ok=True)

        cmd = f"{Constant.LIB_TREE_PATH} -R -in-tree {self.tree_path} " \
              f"-out-res {str(CommonTools.get_work_result_path_by_work_path(self.work_path))}"
        Logger.log_to_file(cmd, path=self.work_path)
        self.processExecutor.execute(
            cmd,
            finished_callback=__on_finish)


if __name__ == '__main__':
    g = Tree6Generator("", "/root/PycharmProjects/IPv6Django/result/123123")
    g.set_params(1, "ipv6_echoscan", "10M")
    g.generate()
