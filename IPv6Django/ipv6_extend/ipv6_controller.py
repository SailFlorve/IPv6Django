import json
import pathlib
import shutil

from django.core.paginator import Paginator, EmptyPage
from django.db.models import QuerySet, Q
from django.http import StreamingHttpResponse, HttpResponse

from IPv6Django.bean.beans import IPv6Params, Status, IPv6Task, PageInfo, IPv6Statistics, UpdateInfo, VulnScript
from IPv6Django.ipv6_extend.constant import Constant
from IPv6Django.ipv6_extend.ipv6_vuln_scan import IPv6VulnerabilityScanner
from IPv6Django.ipv6_extend.ipv6_workflow import IPv6Workflow
from IPv6Django.models import IPv6TaskModel, IPv6TaskSerializer
from IPv6Django.tools.common_tools import CommonTools, ZipTool, Logger
from IPv6Django.tools.custom_response import CustomResponse


# noinspection PyMethodMayBeStatic
class IPv6Controller:

    def __init__(self):
        self.ipv6_workflow_dict: dict[str, IPv6Workflow] = {}

    def start_task(self, task_type: int, name: str, upload_file, budget=0, probe="", band_width="", port="",
                   vuln_params=""):
        return_status = Status.OK
        ipv6 = CommonTools.get_ipv6()
        if ipv6 == "":
            return CustomResponse(Status.NO_IPV6, "")
        elif ipv6.startswith("fe80"):
            return_status = Status.LOCAL_IPV6

        if IPv6TaskModel.objects.filter(task_name=name).exists():
            return CustomResponse(Status.FIELD_EXIST)

        task_id = f"{'G' if task_type == IPv6TaskModel.TYPE_GENERATE else 'V'}-" + CommonTools.get_uuid()

        if task_type == IPv6TaskModel.TYPE_GENERATE:
            ipv6_params = IPv6Params(ipv6, budget, probe, band_width, port, vuln_params)
        else:
            ipv6_params = IPv6Params(ipv6, vuln_params=vuln_params)

        workflow = IPv6Workflow(task_id,
                                ipv6_params,
                                upload_file)
        workflow.set_on_task_finished_callback(self.__on_task_finish)
        self.ipv6_workflow_dict[task_id] = workflow

        if task_type == IPv6TaskModel.TYPE_GENERATE:
            workflow.start_generate_workflow()
        else:
            workflow.start_vulnerability_scan()

        state = IPv6TaskModel.STATE_PREPROCESS if task_type == IPv6TaskModel.TYPE_GENERATE \
            else IPv6TaskModel.STATE_VULN_SCAN
        workflow.current_state = state
        IPv6TaskModel.objects.create(task_id=task_id,
                                     task_name=name,
                                     task_type=task_type,
                                     state=state,
                                     result_path=workflow.work_path,
                                     upload_path=workflow.file_save_path,
                                     params=ipv6_params.to_json(),
                                     result="")

        Logger.log_to_file(f"Task created. Task id: {task_id}, use IPv6: {ipv6}", task_id)
        return CustomResponse(return_status, IPv6Task(task_id, name).to_dict())

    def __get_task_id_list_by_dir(self) -> set:
        """
        从result文件夹里获取所有任务的task_id
        """
        result = set()
        path = pathlib.Path(Constant.RESULT_DIR_PATH)
        if not path.exists():
            return result
        for p in path.iterdir():
            result.add(p.name)
        return result

    def get_tasks_from_db(self, task_type: str, c_page, per_page, task_name: str) -> CustomResponse:
        try:
            task_type = int(task_type)
            c_page = int(c_page)
            per_page = int(per_page)
        except ValueError:
            return CustomResponse(Status.PARAM_ERROR.with_extra("task_type、pageNum或pageSize参数错误"))

        match task_type:
            case IPv6TaskModel.TYPE_GENERATE | IPv6TaskModel.TYPE_VULN_SCAN:
                kwargs_dict = {"task_type": task_type}
                if not (task_name is None or task_name == ""):
                    kwargs_dict["task_name"] = task_name
                query_set = IPv6TaskModel.objects.filter(**kwargs_dict)
            case IPv6TaskModel.TYPE_ALL:
                query_set = IPv6TaskModel.objects.all()
            case _:
                return CustomResponse(Status.PARAM_ERROR.with_extra("task_type参数错误"))

        # serializer = IPv6TaskIdSerializer(query_set, many=True)
        try:
            paginator = Paginator(query_set, per_page)
            page_data: QuerySet = paginator.page(c_page).object_list
        except EmptyPage:
            return CustomResponse(Status.PARAM_ERROR.with_extra("页码错误"))

        page_info = PageInfo(int(c_page), paginator.per_page, query_set.count())
        return CustomResponse(Status.OK, page_data.values(), page_info)

    def task_statistics(self):
        all_count = IPv6TaskModel.objects.count()
        generate_num = IPv6TaskModel.objects.filter(task_type=IPv6TaskModel.TYPE_GENERATE).count()
        vuln_scan_num = IPv6TaskModel.objects.filter(task_type=IPv6TaskModel.TYPE_VULN_SCAN).count()
        generate_running_num = IPv6TaskModel.objects.filter(~Q(state=IPv6TaskModel.STATE_FINISH),
                                                            task_type=IPv6TaskModel.TYPE_GENERATE).count()
        generate_finished_num = IPv6TaskModel.objects.filter(state=IPv6TaskModel.STATE_FINISH,
                                                             task_type=IPv6TaskModel.TYPE_GENERATE).count()
        vuln_scan_running_num = IPv6TaskModel.objects.filter(~Q(state=IPv6TaskModel.STATE_FINISH),
                                                             task_type=IPv6TaskModel.TYPE_VULN_SCAN).count()
        vuln_finished_num = IPv6TaskModel.objects.filter(state=IPv6TaskModel.STATE_FINISH,
                                                         task_type=IPv6TaskModel.TYPE_VULN_SCAN).count()

        ipv6_statistics = IPv6Statistics(all_count, generate_num,
                                         vuln_scan_num,
                                         generate_running_num,
                                         generate_finished_num,
                                         vuln_scan_running_num,
                                         vuln_finished_num)

        return CustomResponse(Status.OK, ipv6_statistics.to_dict())

    def get_task_state(self, task_name) -> CustomResponse:
        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)

        msg = "成功"
        match model.state:
            case IPv6TaskModel.STATE_PREPROCESS:
                msg = "正在预处理IPv6地址"
            case IPv6TaskModel.STATE_GENERATE_IPV6:
                msg = "正在生成IPv6地址"
            case IPv6TaskModel.STATE_VULN_SCAN:
                msg = "正在进行漏洞扫描"
            case IPv6TaskModel.STATE_FINISH:
                msg = "任务已完成"
            case IPv6TaskModel.STATE_ERROR:
                msg = "任务出错"

        return CustomResponse(Status.OK.with_extra(msg), data=IPv6TaskSerializer(model).data)

    def parse_vuln_scan_result(self, task_name: str, page_num: int, page_size: int) -> CustomResponse:
        try:
            page_num = int(page_num)
            page_size = int(page_size)
        except Exception:
            return CustomResponse(Status.PARAM_ERROR.with_extra("pageNum或pageSize参数错误"))

        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)
        if model.state != IPv6TaskModel.STATE_FINISH:
            return CustomResponse(Status.TASK_NOT_FINISHED)

        result_path = CommonTools.get_work_result_path_by_task_id(model.task_id) / (Constant.SCAN_RES_NAME + ".json")
        if not result_path.exists():
            return CustomResponse(Status.FILE_NOT_EXIST.with_extra("结果文件不存在"))

        try:
            result_obj = json.loads(result_path.read_text())
            # page_size = 1就不分页
            page_data = result_obj[(page_num - 1) * page_size: page_num * page_size] if page_size != -1 else result_obj
            page_info = PageInfo(page_num, page_size, len(result_obj))
            return CustomResponse(Status.OK, page_data, page_info=page_info if page_size != -1 else None)

        except Exception as e:
            return CustomResponse(Status.FILE_PARSE_ERROR.with_extra("解析结果文件失败" + str(e)))

    def get_task_result(self, task_name, download_type) -> HttpResponse | StreamingHttpResponse:
        m = self.__get_model_by_task_name(task_name)
        if m is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)

        task_id = m.task_id
        task_set = self.__get_task_id_list_by_dir()
        if task_id not in task_set:
            return CustomResponse(Status.FIELD_NOT_EXIST)

        dir_list = []
        match download_type:
            case 1:
                dir_list.append(str(CommonTools.get_work_result_path_by_task_id(task_id)))
            case 2:
                dir_list.append(str(CommonTools.get_work_result_path_by_task_id(task_id)))
                dir_list.append(CommonTools.get_work_path(task_id) / Constant.TARGET_DIR_PATH)
            case 4:
                dir_list.append(str(pathlib.Path(Constant.UPLOAD_DIR_PATH) / task_id))

        zip_path = CommonTools.get_work_path(task_id)
        zip_name = f"{task_id}.zip"
        return self.__get_zip_response(dir_list, zip_name, zip_path)

    def __get_zip_response(self, dir_list, zip_name, zip_path):
        zip_tool = ZipTool()
        for d in dir_list:
            zip_tool.add_dir(d)
        zip_tool.zip(zip_path / zip_name)

        def file_iterator(file_path, chunk_size=4096):
            with open(file_path, mode='rb') as f:
                while True:
                    c = f.read(chunk_size)
                    if c:
                        yield c
                    else:
                        break

        try:
            response = StreamingHttpResponse(file_iterator(zip_path / zip_name))
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = f'attachment;filename={zip_name}'
        except Exception as e:
            return CustomResponse(Status.RESPONSE_ERROR.with_extra("下载失败"), str(e))
        return response

    def stop_task(self, task_name) -> CustomResponse:
        Logger.log_to_file(f"Stop task - {task_name}")

        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)
        task_id = model.task_id

        ipv6_workflow = self.ipv6_workflow_dict.get(task_id)
        if ipv6_workflow is None:
            return CustomResponse(Status.TASK_NOT_RUNNING)

        result_preprocessor = ipv6_workflow.ipv6_preprocessor.processExecutor.terminate()
        result_generator = ipv6_workflow.ipv6_generator.processExecutor.terminate()
        result_scanner = ipv6_workflow.ipv6_vulnerability_scanner.processExecutor.terminate()

        CommonTools.clear_task_cache(task_id)

        Logger.log_to_file(f"stop preprocessor: {result_preprocessor}", task_id)
        Logger.log_to_file(f"stop generator: {result_generator}", task_id)
        Logger.log_to_file(f"stop scanner: {result_scanner}", task_id)

        return CustomResponse(Status.OK)

    def delete_task(self, task_name):
        Logger.log_to_file(f"Delete task - {task_name}")

        self.stop_task(task_name)

        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)
        task_id = model.task_id

        IPv6TaskModel.objects.get(task_id=task_id).delete()

        CommonTools.delete_task_dir(task_id)

        return CustomResponse(Status.OK)

    def get_scripts(self, page_num, page_size):
        script_list = Constant.vuln_scripts
        page_data = [VulnScript(t[0], t[1]).to_dict()
                     for t in  # page_size = 1就不分页
                     (script_list[(page_num - 1) * page_size: page_num * page_size] if page_size != -1
                      else script_list)]
        page_info = PageInfo(page_num, page_size, len(script_list))
        return CustomResponse(Status.OK, page_data, page_info=page_info if page_size != -1 else None)

    def check_scripts_update(self):
        return CustomResponse(Status.OK.with_extra("当前已经是最新版本"), UpdateInfo(0, ""))

    def __get_model_by_task_name(self, task_name):
        try:
            task_model = IPv6TaskModel.objects.get(task_name=task_name)
        except IPv6TaskModel.DoesNotExist:
            return None

        if task_model is None:
            return None

        return task_model

    def get_log(self, task_name):
        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)
        task_id = model.task_id

        log_path = Logger.get_log_path(task_id)
        text = log_path.read_text(encoding="utf-8")
        return CustomResponse(Status.OK, data={"log": text})

    # 此方法只用于清理缓存 此时数据库还未更新完成
    def __on_task_finish(self, task_id):
        model = IPv6TaskModel.objects.get(task_id=task_id)
        model.state = IPv6TaskModel.STATE_FINISH
        model.save()

        try:
            del self.ipv6_workflow_dict[task_id]
            CommonTools.clear_task_cache(task_id)
            Logger.log_to_file(f"Task {task_id} released", task_id)
        except KeyError:
            pass


if __name__ == '__main__':
    pass
