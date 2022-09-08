import pathlib
import shutil
import time
from typing import Callable

from IPv6Django.bean.beans import IPv6Params, IPv6GenerateTaskResult
from IPv6Django.ipv6_extend.command_parser import CommandParser
from IPv6Django.ipv6_extend.constant import Constant
from IPv6Django.ipv6_extend.ipv6_generator import Tree6Generator
from IPv6Django.ipv6_extend.ipv6_preprocessor import Tree6Preprocessor
from IPv6Django.ipv6_extend.ipv6_vuln_scan import IPv6VulnerabilityScanner
from IPv6Django.models import IPv6TaskModel
from IPv6Django.tools.common_tools import CommonTools, Logger


class IPv6Workflow:
    def __init__(self, task_id: str, params: IPv6Params, upload_file):
        self.upload_file = upload_file
        self.task_id: str = task_id
        self.file_save_path: pathlib.Path = pathlib.Path(
            Constant.UPLOAD_DIR_PATH) / self.task_id / upload_file.name
        self.work_path: pathlib.Path = CommonTools.get_work_path(self.task_id)  # 保存结果的文件夹
        self.ipv6_preprocessor = Tree6Preprocessor(self.file_save_path, self.work_path)
        self.ipv6_generator = Tree6Generator(params.ipv6, self.work_path)
        self.ipv6_vulnerability_scanner = IPv6VulnerabilityScanner(
            self.file_save_path, self.work_path, params.vuln_params)
        self.ipv6_params = params

        self.command_parser = CommandParser()

        self.file_save_path.parent.mkdir(parents=True, exist_ok=True)
        self.work_path.mkdir(parents=True, exist_ok=True)

        self.ipv6_preprocessor.processExecutor.stdout_callback = self.__stdout_callback
        self.ipv6_generator.processExecutor.stdout_callback = self.__stdout_callback
        self.ipv6_vulnerability_scanner.processExecutor.stdout_callback = self.__stdout_callback

        self.target_index = 0
        self.last_line_count = 0
        self.all_line_count = 0  # targets.txt中的总行数
        self.current_state = IPv6TaskModel.STATE_PREPROCESS

        self.generate_result = IPv6GenerateTaskResult(int(params.budget), int(params.budget))

        self.on_task_finished_callback: Callable[[str], None] | None = None

    def start_generate_workflow(self):
        Logger.log_to_file("start_workflow", self.task_id)
        self.__save_file()
        self.ipv6_preprocessor.set_finished_callback(self.__on_preprocess_finished)
        self.ipv6_preprocessor.run()

    def start_vulnerability_scan(self):
        Logger.log_to_file("start_vulnerability_scan", self.task_id)
        self.__save_file()
        self.ipv6_vulnerability_scanner.set_on_finish_callback(self.__on_vulnerability_scan_finished)
        self.ipv6_vulnerability_scanner.scan()

    def set_on_task_finished_callback(self, callback):
        self.on_task_finished_callback = callback

    def __save_file(self):
        with open(self.file_save_path, 'wb') as destination:
            for chunk in self.upload_file.chunks():
                destination.write(chunk)

    def __on_preprocess_finished(self, return_code, line_count):

        Logger.log_to_file(f"preprocess finished, return code {return_code}, line count {line_count}", self.task_id)

        if return_code != 0:
            self.generate_result.parse_cmd_1 = f"预处理失败，错误{return_code}"
            self.__update_result()
            self.__set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        if line_count == 0:
            self.generate_result.parse_cmd_1 = "没有可用的IPv6地址"
            self.__update_result()
            self.__set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        self.ipv6_params.valid_upload_addr = line_count
        model = IPv6TaskModel.get_model_by_task_id(self.task_id)
        if model is not None:
            model.params = self.ipv6_params.to_json()
            model.save()

        time.sleep(3)
        self.ipv6_generator.set_params(self.ipv6_params.budget,
                                       self.ipv6_params.probe,
                                       self.ipv6_params.band_width,
                                       self.ipv6_params.port)
        self.ipv6_generator.set_finished_callback(self.__on_generate_finished)
        self.ipv6_generator.generate()
        self.__set_current_state(IPv6TaskModel.STATE_GENERATE_IPV6)

    def __on_generate_finished(self, return_code):
        Logger.log_to_file(f"generate finished, return {return_code}", self.task_id)
        if return_code is not 0:
            self.generate_result.parse_cmd_1 = f"生成IPv6地址失败，错误{return_code}"
            self.__update_result()
            self.__set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        # 进行精确统计
        self.generate_result.address_generated = self.all_line_count
        self.generate_result.generated_addr_example = CommonTools.get_target_addr_examples_json(self.task_id)
        self.generate_result.budget_left = int(self.ipv6_params.budget) - self.all_line_count
        self.generate_result.hit_rate = self.generate_result.total_active / self.all_line_count

        self.__set_current_state(IPv6TaskModel.STATE_FINISH)

        # 先使外部处理缓存文件
        if self.on_task_finished_callback is not None:
            self.on_task_finished_callback(self.task_id)

        # 再统计文件夹size并更新数据库
        self.__set_dir_size()
        self.__update_result()

    def __on_vulnerability_scan_finished(self, exit_code):
        Logger.log_to_file(f"vulnerability scan finished, exit code {exit_code}", self.task_id)
        if exit_code != 0:
            self.generate_result.parse_cmd_1 = f"扫描IPv6漏洞失败，错误{exit_code}"
            self.__update_result()
            self.__set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        self.__set_current_state(IPv6TaskModel.STATE_FINISH)
        if self.on_task_finished_callback is not None:
            self.on_task_finished_callback(self.task_id)

        self.__set_dir_size()
        self.__update_result()

    def __stdout_callback(self, cmd_line):
        Logger.log_to_file(cmd_line, self.task_id)
        self.generate_result.current_cmd = cmd_line

        if self.current_state == IPv6TaskModel.STATE_VULN_SCAN:
            self.__update_result()
            return

        msg_type, msg_info = self.command_parser.parse(cmd_line)

        match msg_type:
            case CommandParser.TYPE_ZMAP_START:
                line_count = CommonTools.line_count(str(self.work_path / Constant.TARGET_TMP_PATH))
                self.last_line_count = line_count
                self.all_line_count += line_count
                self.__copy_targets()
            case CommandParser.TYPE_SENDING:
                current = msg_info[0]
                self.__set_current_parse_cmd(1, f"活动地址探测: {current} / {self.last_line_count}")
                self.generate_result.current_scan = current
                self.generate_result.all_scan = self.last_line_count
                self.__update_result()

            case CommandParser.TYPE_BUDGET:
                self.generate_result.budget_left = msg_info[0]
                self.__update_result()
                self.__set_current_parse_cmd(2, f"剩余预算: {self.generate_result.budget_left}")
            case CommandParser.TYPE_FINISH:
                all_generate = self.generate_result.all_budget - self.generate_result.budget_left
                total_active = msg_info[0]
                hit_rate = int(total_active) / all_generate
                parse_msg = f"找到活动地址: {total_active}, 已扩展: {all_generate}, " \
                            f"命中率: {hit_rate}"
                self.generate_result.address_generated = all_generate
                self.generate_result.total_active = total_active
                self.generate_result.hit_rate = hit_rate

                self.__update_result()
                self.__set_current_parse_cmd(1, parse_msg)
                self.__set_current_parse_cmd(2, "")
            case CommandParser.TYPE_6TREE_START:
                self.target_index = 0
                self.__set_current_parse_cmd(2, f"剩余预算: {self.generate_result.all_budget}")
            case CommandParser.TYPE_6TREE_TRANS:
                self.__set_current_parse_cmd(2, "状态: 正在预处理...")
            case CommandParser.TYPE_6TREE_TRANS_FINISH:
                self.__set_current_parse_cmd(2, "状态: 地址预处理完成")

    def __set_current_parse_cmd(self, pos: int, msg):
        if pos == 1:
            self.generate_result.current_parse_cmd_1 = msg
        elif pos == 2:
            self.generate_result.current_parse_cmd_2 = msg

        Logger.log_to_file(msg, self.task_id)

        self.__update_result()

    def __copy_targets(self):
        path = self.work_path / Constant.TARGET_DIR_PATH
        path.mkdir(parents=True, exist_ok=True)

        shutil.copyfile(self.work_path / Constant.TARGET_TMP_PATH,
                        path / f"targets_{self.target_index}.txt")
        Logger.log_to_file(f"Copy targets {self.target_index}", self.task_id)
        self.target_index += 1

    def __update_result(self, result=""):
        if result == "":
            result = self.generate_result.to_json()
        IPv6TaskModel.update_result(self.task_id, result)

    def __set_current_state(self, current_state):
        self.current_state = current_state
        IPv6TaskModel.update_state(self.task_id, current_state)

    def __set_dir_size(self):
        all_file_size = CommonTools.get_dir_size(str(self.work_path.resolve()))
        result_file_size = CommonTools.get_dir_size(
            str(CommonTools.get_work_result_path_by_task_id(self.task_id).resolve()))
        self.generate_result.all_file_size = all_file_size
        self.generate_result.result_file_size = result_file_size
