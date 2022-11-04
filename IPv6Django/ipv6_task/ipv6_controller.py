import json
import pathlib

from django.core.paginator import Paginator, EmptyPage
from django.db.models import QuerySet, Q
from django.http import StreamingHttpResponse, HttpResponse, FileResponse

from IPv6Django.bean.beans import IPv6TaskParams, Status, IPv6Task, PageInfo, IPv6Statistics, UpdateInfo
from IPv6Django.constant.constant import Constant
from IPv6Django.ipv6_task.ipv6_workflow import IPv6Workflow
from IPv6Django.models import IPv6TaskModel, IPv6TaskSerializer, VulnScriptModel
from IPv6Django.tools.common_tools import CommonTools, ZipTool
from IPv6Django.tools.logger import Logger
from IPv6Django.tools.vuln_script_manager import VulnScriptManager
from IPv6Django.tools.custom_response import CustomResponse


# noinspection PyMethodMayBeStatic
class IPv6Controller:
    """
    提供view层调用的接口
    """

    def __init__(self):
        self.ipv6_workflow_dict: dict[str, IPv6Workflow] = {}

    def start_task(self, f, params: IPv6TaskParams):

        if IPv6TaskModel.objects.filter(task_name=params.task_name).exists():
            return CustomResponse(Status.FIELD_EXIST)

        return_status = Status.OK
        ipv6 = CommonTools.get_ipv6()
        if ipv6 == "":
            return CustomResponse(Status.NO_IPV6, "")
        elif ipv6.startswith("fe80"):
            if params.allow_local_ipv6 == 0:
                return CustomResponse(Status.LOCAL_IPV6.with_extra(
                    f"IPv6地址是{ipv6}，为本地回环IPv6地址。如果需要使用此IPv6地址开启任务，请传递参数local=1"))
            return_status = Status.LOCAL_IPV6
        else:
            pass

        params.ipv6 = ipv6

        task_id = self.get_task_id(params.task_type)

        workflow = IPv6Workflow.create(params.task_type, task_id,
                                       params, f)
        workflow.set_on_task_finished_callback(self.__on_task_finish)
        self.ipv6_workflow_dict[task_id] = workflow

        IPv6TaskModel.objects.create(task_id=task_id,
                                     task_name=params.task_name,
                                     task_type=params.task_type,
                                     state=workflow.current_state,
                                     result_path=workflow.work_path,  # work_path在workflow的构造函数中被自动生成
                                     upload_path=workflow.file_save_path,
                                     params=params.to_json(),
                                     result="")

        workflow.start()

        Logger.log_to_file(f"Task created. Task id: {task_id}, use IPv6: {ipv6}", task_id)
        return CustomResponse(return_status, IPv6Task(task_id, params.task_name, ipv6).to_dict())

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
            case IPv6TaskModel.TYPE_GENERATE | IPv6TaskModel.TYPE_VULN_SCAN | IPv6TaskModel.TYPE_STABILITY:
                # 按类别查询，task_name可选
                kwargs_dict = {"task_type": task_type}
                if not (task_name is None or task_name == ""):
                    kwargs_dict["task_name"] = task_name
                query_set = IPv6TaskModel.objects.filter(**kwargs_dict)
            case IPv6TaskModel.TYPE_ALL:
                # 查询所有
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

    def get_task_statistics(self):
        all_count = IPv6TaskModel.objects.count()
        type_list = [IPv6TaskModel.TYPE_GENERATE, IPv6TaskModel.TYPE_VULN_SCAN, IPv6TaskModel.TYPE_STABILITY]

        ipv6_statistics = IPv6Statistics(all_count)

        for task_type in type_list:
            task_all = IPv6TaskModel.objects.filter(task_type=task_type).count()
            task_running = IPv6TaskModel.objects.filter(~Q(state=IPv6TaskModel.STATE_FINISH),
                                                        task_type=task_type).count()
            task_finished = IPv6TaskModel.objects.filter(state=IPv6TaskModel.STATE_FINISH,
                                                         task_type=task_type).count()
            ipv6_statistics.add(task_type, task_all, task_running, task_finished)

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
        """
        解析漏洞扫描结果。其解析结果已经在漏洞扫描结束时生成并保存Json文件，此方法读取那个文件并分页
        """
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
            # page_size = -1就不分页
            page_data = result_obj[(page_num - 1) * page_size: page_num * page_size] if page_size != -1 else result_obj
            page_info = PageInfo(page_num, page_size, len(result_obj))
            return CustomResponse(Status.OK, page_data, page_info=page_info if page_size != -1 else None)

        except Exception as e:
            return CustomResponse(Status.FILE_PARSE_ERROR.with_extra("解析结果文件失败" + str(e)))

    def get_task_result(self, task_name, download_type) -> HttpResponse | StreamingHttpResponse:
        """
        用于下载zip文件
        """
        m = self.__get_model_by_task_name(task_name)
        if m is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)

        task_id = m.task_id
        task_set = self.__get_task_id_list_by_dir()
        if task_id not in task_set:
            return CustomResponse(Status.FIELD_NOT_EXIST)

        dir_list = []
        match download_type:
            case IPv6TaskModel.TYPE_GET_RESULT:
                dir_list.append(str(CommonTools.get_work_result_path_by_task_id(task_id)))
            case IPv6TaskModel.TYPE_GET_PREPROCESS:
                # dir_list.append(str(CommonTools.get_work_result_path_by_task_id(task_id)))
                # dir_list.append(CommonTools.get_work_path(task_id) / Constant.TARGET_DIR_PATH)
                dir_list.append(CommonTools.get_work_path(task_id) / Constant.PREPROCESS_DIR)
            case IPv6TaskModel.TYPE_GET_UPLOAD:
                dir_list.append(str(pathlib.Path(Constant.UPLOAD_DIR_PATH) / task_id))
            case IPv6TaskModel.TYPE_GET_GENERATION:
                dir_list.append(CommonTools.get_work_path(task_id) / Constant.TARGET_DIR_PATH)

        zip_path = CommonTools.get_work_path(task_id)
        zip_name = f"{task_id}.zip"
        return self.__get_zip_response(dir_list, zip_name, zip_path)

    def __get_zip_response(self, dir_list, zip_name, zip_path):
        """
        创建了一个响应流，包含了zip文件
        """
        zip_tool = ZipTool()
        for d in dir_list:
            zip_tool.add_dir(d)
        zip_tool.zip(zip_path / zip_name)

        # def file_iterator(file_path, chunk_size=4096):
        #     with open(file_path, mode='rb') as f:
        #         while True:
        #             c = f.read(chunk_size)
        #             if c:
        #                 yield c
        #             else:
        #                 break

        try:
            response = FileResponse(open(zip_path / zip_name, 'rb'))
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = f'attachment;filename={zip_name}'
        except Exception as e:
            return CustomResponse(Status.RESPONSE_ERROR.with_extra("下载失败"), str(e))
        return response

    def stop_task(self, task_name) -> CustomResponse:

        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)
        task_id = model.task_id

        Logger.log_to_file(f"Stop task - {task_name}", task_id)

        ipv6_workflow = self.ipv6_workflow_dict.get(task_id)
        if ipv6_workflow is None:
            return CustomResponse(Status.TASK_NOT_RUNNING)

        ipv6_workflow.stop()

        CommonTools.clear_task_cache(task_id)
        model.state = IPv6TaskModel.STATE_INTERRUPT
        model.save()

        return CustomResponse(Status.OK)

    def delete_task(self, task_name):

        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)
        task_id = model.task_id

        Logger.log_to_file(f"Delete task - {task_name}", task_id)

        self.stop_task(task_name)

        IPv6TaskModel.objects.get(task_id=task_id).delete()

        CommonTools.delete_task_dir(task_id)

        return CustomResponse(Status.OK)

    def get_scripts(self, page_num, page_size):
        VulnScriptManager.init_db_if_empty()

        query_set = VulnScriptModel.objects.all()
        paginator = Paginator(query_set, page_size)
        page_data: QuerySet = paginator.page(page_num).object_list

        page_info = PageInfo(page_num, page_size, query_set.count())
        return CustomResponse(Status.OK, page_data.values(), page_info=page_info if page_size != -1 else None)

    def check_scripts_update(self):
        try:
            scripts = VulnScriptManager.load_scripts()
        except Exception as e:
            return CustomResponse(Status.UPDATE_SCRIPTS_ERROR.with_extra(str(e)))

        loaded_scripts_set = frozenset(scripts)
        query_set = VulnScriptModel.objects.all()
        local_scripts_set = frozenset([model for model in query_set])

        if loaded_scripts_set == local_scripts_set:
            return CustomResponse(Status.OK.with_extra("当前已经是最新版本"), UpdateInfo(0, ""))
        else:
            for script_model in scripts:
                VulnScriptModel.objects.get_or_create(name=script_model.name, description=script_model.description)
            scripts_diff = len(loaded_scripts_set.difference(local_scripts_set))
            return CustomResponse(Status.OK.with_extra(f"更新了{scripts_diff}条数据"), UpdateInfo(scripts_diff, ""))

    def delete_scripts(self):
        try:
            VulnScriptModel.objects.all().delete()
            return CustomResponse(Status.OK)
        except Exception as e:
            return CustomResponse(Status.DELETE_ERROR.with_extra(str(e)))

    def get_log(self, task_name):
        model = self.__get_model_by_task_name(task_name)
        if model is None:
            return CustomResponse(Status.FIELD_NOT_EXIST)
        task_id = model.task_id

        log_path = Logger.get_log_path(task_id)
        text = log_path.read_text(encoding="utf-8")
        return CustomResponse(Status.OK, data={"log": text})

    def __get_model_by_task_name(self, task_name):
        try:
            task_model = IPv6TaskModel.objects.get(task_name=task_name)
        except IPv6TaskModel.DoesNotExist:
            return None

        if task_model is None:
            return None

        return task_model

    # 此方法只用于清理缓存 此时数据库还未更新完成
    # 在ipv6_workflow的__on_generate_finished和__on_vulnerability_scan_finished中调用后，
    # 会统计清理后的文件夹大小，再更新到数据库
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

    @staticmethod
    def get_task_id(task_type: int) -> str:
        prefix: str
        match task_type:
            case IPv6TaskModel.TYPE_GENERATE:
                prefix = "G"
            case IPv6TaskModel.TYPE_VULN_SCAN:
                prefix = "V"
            case IPv6TaskModel.TYPE_STABILITY:
                prefix = "S"
            case _:
                prefix = "T"
        task_id: str = f"{prefix}-{CommonTools.get_uuid()}"
        return task_id


if __name__ == '__main__':
    pass
