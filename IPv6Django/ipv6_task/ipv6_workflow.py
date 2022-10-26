import pathlib
import shutil
import time
from abc import abstractmethod
from typing import Callable

from IPv6Django.bean.beans import IPv6TaskParams, IPv6GenerateTaskResult, IPv6VulnScanTaskResult, IPv6StabilityResult, \
    IPv6TaskResult
from IPv6Django.constant.constant import Constant
from IPv6Django.tools.ipv6_classification import IPv6MultiLevelClassification
from IPv6Django.tools.ipv6_extend_policy import IPv6ExtendPolicyGenerator
from IPv6Django.ipv6_task.ipv6_generator import Tree6Generator
from IPv6Django.ipv6_task.ipv6_preprocessor import Tree6Preprocessor
from IPv6Django.ipv6_task.ipv6_stability_monitor import IPv6StabilityMonitor
from IPv6Django.ipv6_task.ipv6_vuln_scan import IPv6VulnerabilityScanner
from IPv6Django.models import IPv6TaskModel
from IPv6Django.tools.command_parser import CommandParser
from IPv6Django.tools.common_tools import CommonTools, Logger


class IPv6Workflow:
    """
    管理一个IPv6地址预处理、地址扩展探测、漏洞扫描的执行流程，保存执行状态，并处理相关的文件和结果、写入数据库等
    """

    def __init__(self, task_id: str, params: IPv6TaskParams, upload_file):
        self.task_type: int = -1
        self.upload_file = upload_file
        self.task_id: str = task_id
        self.file_save_path: pathlib.Path = pathlib.Path(
            Constant.UPLOAD_DIR_PATH) / self.task_id / upload_file.name
        self.work_path: pathlib.Path = CommonTools.get_work_path(self.task_id)  # 保存结果的文件夹

        self.ipv6_params = params

        self.command_parser = CommandParser()

        self.file_save_path.parent.mkdir(parents=True, exist_ok=True)
        self.work_path.mkdir(parents=True, exist_ok=True)

        self.current_state = 0

        self.result_obj: IPv6TaskResult | IPv6GenerateTaskResult | IPv6VulnScanTaskResult | IPv6StabilityResult \
            = self._get_task_result_obj()

        self.on_task_finished_callback: Callable[[str], None] | None = None

    @staticmethod
    def create(task_type: int, task_id: str, params: IPv6TaskParams, upload_file) -> 'IPv6Workflow':
        match task_type:
            case IPv6TaskModel.TYPE_GENERATE:
                workflow = IPv6GenerateWorkflow(task_id, params, upload_file)
            case IPv6TaskModel.TYPE_VULN_SCAN:
                workflow = IPv6VulnerabilityScanWorkflow(task_id, params, upload_file)
            case IPv6TaskModel.TYPE_STABILITY:
                workflow = IPv6StabilityWorkflow(task_id, params, upload_file)
            case _:
                raise Exception("未知的任务类型")

        workflow.task_type = task_type
        return workflow

    @abstractmethod
    def start(self):
        self._save_upload_file()

        match self.task_type:
            case IPv6TaskModel.TYPE_GENERATE:
                self.current_state = IPv6TaskModel.STATE_PREPROCESS
            case IPv6TaskModel.TYPE_VULN_SCAN:
                self.current_state = IPv6TaskModel.STATE_VULN_SCAN
            case IPv6TaskModel.TYPE_STABILITY:
                self.current_state = IPv6TaskModel.STATE_STABILITY
            case _:
                pass

    @abstractmethod
    def stop(self):
        pass

    @abstractmethod
    def _on_task_finished(self, exit_code):
        self._set_current_state(IPv6TaskModel.STATE_FINISH)

        # 先使外部处理缓存文件
        if self.on_task_finished_callback is not None:
            self.on_task_finished_callback(self.task_id)

        # 再统计文件夹size并更新数据库
        self._set_dir_size()
        self._update_result()

    @abstractmethod
    def _stdout_callback(self, cmd_line):
        Logger.log_to_file(cmd_line, self.task_id)
        self.result_obj.current_cmd = cmd_line
        self._update_result()

    @abstractmethod
    def _get_task_result_obj(self):
        pass

    def set_on_task_finished_callback(self, callback):
        self.on_task_finished_callback = callback

    def _save_upload_file(self):
        """
        把用户上传的文件流保存到本地
        """
        with open(self.file_save_path, 'wb') as destination:
            for chunk in self.upload_file.chunks():
                destination.write(chunk)

    def _set_current_parse_cmd(self, pos: int, msg):
        if pos == 1:
            self.result_obj.current_parse_cmd_1 = msg
        elif pos == 2:
            self.result_obj.current_parse_cmd_2 = msg

        Logger.log_to_file(msg, self.task_id)

        self._update_result()

    def _update_result(self, result=""):
        if result == "":
            result = self.result_obj.to_json()
        IPv6TaskModel.update_result(self.task_id, result)

    def _set_current_state(self, current_state):
        self.current_state = current_state
        IPv6TaskModel.update_state(self.task_id, current_state)

    def _set_dir_size(self):
        all_file_size = CommonTools.get_dir_size(str(self.work_path.resolve()))
        result_file_size = CommonTools.get_dir_size(
            str(CommonTools.get_work_result_path_by_task_id(self.task_id).resolve()))
        self.result_obj.all_file_size = all_file_size
        self.result_obj.result_file_size = result_file_size


class IPv6GenerateWorkflow(IPv6Workflow):
    def __init__(self, task_id: str, params: IPv6TaskParams, upload_file):
        super(IPv6GenerateWorkflow, self).__init__(task_id, params, upload_file)

        self.ipv6_preprocessor = Tree6Preprocessor(self.file_save_path, self.work_path)
        self.ipv6_generator = Tree6Generator(params.ipv6, self.work_path)

        self.ipv6_preprocessor.set_finished_callback(self._stdout_callback)
        self.ipv6_generator.set_cmd_out_callback(self._stdout_callback)

        self.target_index = 0  # 地址扩展中另存为生成的target的编号
        self.last_line_count = 0
        self.all_line_count = 0  # targets.txt中的总行数

    def start(self):
        super(IPv6GenerateWorkflow, self).start()
        self.__start_generate_workflow()

    def stop(self):
        result_preprocessor = self.ipv6_preprocessor.process_executor.terminate()
        result_generator = self.ipv6_generator.process_executor.terminate()
        Logger.log_to_file(f"Stop preprocessor: {result_preprocessor}", self.task_id)
        Logger.log_to_file(f"Stop generator: {result_generator}", self.task_id)

    def __start_generate_workflow(self):
        Logger.log_to_file("Start_workflow", self.task_id)
        self._save_upload_file()
        self.ipv6_preprocessor.set_finished_callback(self.__on_preprocess_finished)
        self.ipv6_preprocessor.run()

    def __on_preprocess_finished(self, return_code, line_count):

        Logger.log_to_file(f"Preprocess finished, return code {return_code}, line count {line_count}", self.task_id)

        if return_code != 0:
            self.result_obj.parse_cmd_1 = f"预处理失败，错误{return_code}"
            self._update_result()
            self._set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        if line_count == 0:
            self.result_obj.parse_cmd_1 = "没有可用的IPv6地址"
            self._update_result()
            self._set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        self.result_obj.valid_upload_addr = line_count
        self._update_result()

        # 此处可以从数据库获取到数据，调用ipv6_workflow前已经保存了一条任务记录
        model = IPv6TaskModel.get_model_by_task_id(self.task_id)
        if model is not None:
            model.params = self.ipv6_params.to_json()
            model.save()

        policy_generator = IPv6ExtendPolicyGenerator(self.work_path, self.work_path / Constant.TREE_DIR_PATH)
        policy_generator.output_policy()
        del policy_generator

        level_classification = IPv6MultiLevelClassification(self.work_path, self.file_save_path)
        level_classification.multi_level_classification()

        time.sleep(1)
        self.ipv6_generator.set_params(self.ipv6_params.budget,
                                       self.ipv6_params.probe,
                                       self.ipv6_params.rate,
                                       self.ipv6_params.port,
                                       self.ipv6_params.alias_det)
        self.ipv6_generator.set_finished_callback(self._on_task_finished)
        self.ipv6_generator.run()
        self._set_current_state(IPv6TaskModel.STATE_GENERATE_IPV6)

    def _on_task_finished(self, return_code):
        Logger.log_to_file(f"Generate finished, return {return_code}", self.task_id)
        if return_code is not 0:
            self.result_obj.parse_cmd_1 = f"生成IPv6地址发生错误{return_code}"
            self._update_result()
            self._set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        # 进行精确统计
        self.result_obj.address_generated = self.all_line_count
        self.result_obj.generated_addr_example = CommonTools.get_target_addr_examples_json(self.task_id)
        self.result_obj.budget_left = int(self.ipv6_params.budget) - self.all_line_count
        self.result_obj.hit_rate = self.result_obj.total_active / self.all_line_count

        Logger.log_to_file(f"Merging target files", self.task_id)
        # 将所有targets文件合并成一个
        CommonTools.merge_all_file(self.work_path / Constant.TARGET_DIR_PATH,
                                   self.work_path / Constant.TARGET_DIR_PATH / Constant.TARGET_MERGE_NAME)
        Logger.log_to_file(f"Merging finished", self.task_id)

        super(IPv6GenerateWorkflow, self)._on_task_finished(return_code)

    def _stdout_callback(self, cmd_line):
        super(IPv6GenerateWorkflow, self)._stdout_callback(cmd_line)

        msg_type, msg_info = self.command_parser.parse(cmd_line)

        match msg_type:
            case CommandParser.TYPE_ZMAP_START:
                line_count = CommonTools.line_count(str(self.work_path / Constant.TARGET_TMP_PATH))
                self.last_line_count = line_count
                self.all_line_count += line_count
                if line_count != 0:
                    self.__copy_targets()
            case CommandParser.TYPE_SENDING:
                current = msg_info[0]
                self._set_current_parse_cmd(1, f"Active address detection progress: {current} / {self.last_line_count}")
                self.result_obj.current_scan = current
                self.result_obj.all_scan = self.last_line_count
                self._update_result()

            case CommandParser.TYPE_BUDGET:
                self.result_obj.budget_left = msg_info[0]
                self._update_result()
                self._set_current_parse_cmd(2, f"Budget left: {self.result_obj.budget_left}")
            case CommandParser.TYPE_FINISH:
                all_generate = self.result_obj.all_budget - self.result_obj.budget_left
                total_active = msg_info[0]
                hit_rate = int(total_active) / all_generate
                parse_msg = f"Find active address: {total_active}, generated: {all_generate}, " \
                            f"hit rate: {hit_rate}"
                self.result_obj.address_generated = all_generate
                self.result_obj.total_active = total_active
                self.result_obj.hit_rate = hit_rate

                self._update_result()
                self._set_current_parse_cmd(1, parse_msg)
                self._set_current_parse_cmd(2, "")
            case CommandParser.TYPE_6TREE_START:
                self.target_index = 0
                self._set_current_parse_cmd(2, f"Budget left: {self.result_obj.all_budget}")
            case CommandParser.TYPE_6TREE_TRANS:
                self._set_current_parse_cmd(2, "State: preprocessing...")
            case CommandParser.TYPE_6TREE_TRANS_FINISH:
                self._set_current_parse_cmd(2, "State: preprocess finished")

    def __copy_targets(self):
        """
        另存target.txt文件，因为它是临时文件，会被删掉
        """
        path = self.work_path / Constant.TARGET_DIR_PATH
        path.mkdir(parents=True, exist_ok=True)

        shutil.copyfile(self.work_path / Constant.TARGET_TMP_PATH,
                        path / f"targets_{self.target_index}.txt")
        Logger.log_to_file(f"Copy targets {self.target_index}", self.task_id)
        self.target_index += 1

    def _get_task_result_obj(self) -> IPv6GenerateTaskResult:
        return IPv6GenerateTaskResult(int(self.ipv6_params.budget), int(self.ipv6_params.budget))


class IPv6VulnerabilityScanWorkflow(IPv6Workflow):
    def __init__(self, task_id: str, params: IPv6TaskParams, upload_file):
        super(IPv6VulnerabilityScanWorkflow, self).__init__(task_id, params, upload_file)
        self.ipv6_vulnerability_scanner = IPv6VulnerabilityScanner(
            self.file_save_path, self.work_path, params.vuln_params)
        self.ipv6_vulnerability_scanner.set_cmd_out_callback(self._stdout_callback)

    def start(self):
        super(IPv6VulnerabilityScanWorkflow, self).start()
        self.__start_vulnerability_scan()

    def stop(self):
        result_scanner = self.ipv6_vulnerability_scanner.process_executor.terminate()
        Logger.log_to_file(f"Stop scanner: {result_scanner}", self.task_id)

    def __start_vulnerability_scan(self):
        self.ipv6_vulnerability_scanner.set_finished_callback(self._on_task_finished)
        self.ipv6_vulnerability_scanner.scan()

    def _on_task_finished(self, exit_code):
        Logger.log_to_file(f"vulnerability scan finished, exit code {exit_code}", self.task_id)
        if exit_code != 0:
            self.result_obj.parse_cmd_1 = f"扫描IPv6漏洞失败，错误{exit_code}"
            self._update_result()
            self._set_current_state(IPv6TaskModel.STATE_ERROR)
            return

        super(IPv6VulnerabilityScanWorkflow, self)._on_task_finished(exit_code)

    def _stdout_callback(self, cmd_line):
        super(IPv6VulnerabilityScanWorkflow, self)._stdout_callback(cmd_line)

    def _get_task_result_obj(self) -> IPv6VulnScanTaskResult:
        return IPv6VulnScanTaskResult()


class IPv6StabilityWorkflow(IPv6Workflow):
    def __init__(self, task_id: str, params: IPv6TaskParams, upload_file):
        super(IPv6StabilityWorkflow, self).__init__(task_id, params, upload_file)
        self.ipv6_stability_monitor = IPv6StabilityMonitor(self.file_save_path, self.work_path, params)
        self.ipv6_stability_monitor.set_cmd_out_callback(self._stdout_callback)
        self.ipv6_stability_monitor.set_single_monitor_finish_callback(self.__on_single_monitor_finish)
        self.ipv6_stability_monitor.set_finished_callback(self._on_task_finished)

    def start(self):
        super(IPv6StabilityWorkflow, self).start()
        self.result_obj.all_scan = CommonTools.line_count(self.file_save_path)
        Logger.log_to_file(f"Start stability monitor", self.task_id)
        self.ipv6_stability_monitor.run()

    def stop(self):
        Logger.log_to_file(f"Stop stability monitor", self.task_id)
        self.ipv6_stability_monitor.stop()

    def _on_task_finished(self, exit_code):
        Logger.log_to_file(f"Stability monitor finished, exit code {exit_code}", self.task_id)
        super(IPv6StabilityWorkflow, self)._on_task_finished(exit_code)

    def _stdout_callback(self, cmd_line):
        super(IPv6StabilityWorkflow, self)._stdout_callback(cmd_line)

        msg_type, msg_info = self.command_parser.parse(cmd_line)
        match msg_type:
            case CommandParser.TYPE_SENDING:
                self._set_current_parse_cmd(1, f"Scan progress: {msg_info[0]}/{self.result_obj.all_scan}")
                self._set_current_parse_cmd(2, f"Current hit rate: {msg_info[1]}")
                self.result_obj.current_time = self.ipv6_stability_monitor.current_time
                self.result_obj.current_scan = msg_info[0]
                self.result_obj.current_hit_rate = msg_info[1]
                self._update_result()

    def _get_task_result_obj(self) -> 'IPv6StabilityResult':
        return IPv6StabilityResult()

    def __on_single_monitor_finish(self):
        self.result_obj.save()
        self._update_result()
        Logger.log_to_file(f"Current hit rate: {self.result_obj.current_hit_rate}, "
                           f"Average hit rate: {self.result_obj.ave_hit_rate}", self.task_id)
