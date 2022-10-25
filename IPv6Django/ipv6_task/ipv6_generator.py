from os import PathLike

from IPv6Django.constant.constant import Constant
from IPv6Django.ipv6_task.ipv6_task_base import IPv6TaskBase
from IPv6Django.tools.common_tools import CommonTools, Logger


class Tree6Generator(IPv6TaskBase):
    def __init__(self, ipv6: str, work_path_str: str | PathLike[str]):
        super(Tree6Generator, self).__init__(work_path_str)
        self.search_params = None
        self.scanner_params = None
        self.tree_path = (self.work_path / Constant.TREE_DIR_PATH)
        self.ipv6 = ipv6

    def run(self):
        self.__generate()

    def stop(self):
        super().stop()

    def set_params(self, budget: int, probe: str, rate: str, port: str = "", alias_det: int = 0):
        use_port: bool = (probe != "icmp6_echoscan")

        self.search_params = f'''budget : {budget}
step_budget : {int(budget) / 5}
adet_ptimes : {alias_det}
adet_tsscale_thd : 1024
adet_aad_thd : 0.95
adet_crip : 1048576'''

        self.scanner_params = f"""app_name : zmap
ins_num : {8 if use_port else 7}
--probe-module={probe}
--ipv6-target-file={str(self.work_path / Constant.TARGET_TMP_PATH)}
--output-file={str(self.work_path / Constant.RESULT_TMP_PATH)}
--ipv6-source-ip={self.ipv6}
--rate={rate}
--cooldown-time=4
--verbosity=3"""

        if use_port:
            self.scanner_params += f"\n--target-port={port}"

        tree_scanner_path = self.tree_path / "scanner_parameters"
        tree_scanner_path.write_text(self.scanner_params)

        tree_search_path = self.tree_path / "search_parameters"
        tree_search_path.write_text(self.search_params)

    def __generate(self):
        def __on_finish(result):
            Logger.log_to_file(f"Generate return code: {result}", path=self.work_path)
            if self.finished_callback is not None:
                self.finished_callback(result)

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
        self.process_executor.execute(
            cmd,
            finished_callback=__on_finish)


if __name__ == '__main__':
    g = Tree6Generator("", "/root/PycharmProjects/IPv6Django/result/123123")
    g.set_params(1, "ipv6_echoscan", "10M")
    g.run()
