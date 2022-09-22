from rest_framework.request import Request
from rest_framework.views import APIView

from IPv6Django.bean.beans import Status
from IPv6Django.models import IPv6TaskModel
from IPv6Django.tools.common_tools import CommonTools
from IPv6Django.tools.custom_response import CustomResponse
from IPv6Django.tools.decorators import request_verify, CheckType
from IPv6Django.tools.singleton import Singleton

'''
POST 开启扩展和扫描(2)
ipv6_task?type=X&...

GET 获取列表(2)
ipv6_task/?type=0,1&current_page&per_page
'''


class IPv6TaskAPIView(APIView):

    def __init__(self):
        super(IPv6TaskAPIView, self).__init__()
        self.ipv6_manager = Singleton.get_ipv6_controller()

    @request_verify(require_params=['type', 'name'],
                    require_form_datas=['ipv6_file'],
                    check_types=[CheckType('type',
                                           'int',
                                           [IPv6TaskModel.TYPE_GENERATE, IPv6TaskModel.TYPE_VULN_SCAN])])
    def post(self, request: Request):
        f = request.FILES.get('ipv6_file')
        name = request.query_params.get('name')
        budget = request.query_params.get('budget')
        probe = request.query_params.get('probe')
        band_width = request.query_params.get('band_width')
        port = request.query_params.get('port')
        task_type = int(request.query_params.get('type'))
        vuln_params = request.query_params.get('vuln_params')

        if task_type == IPv6TaskModel.TYPE_GENERATE:
            if not CommonTools.require_not_none(name, budget, probe, band_width, port):
                return CustomResponse(Status.LACK_PARAM, msg='name, budget, probe, band_width, port 中的参数不能为空')

        return self.ipv6_manager.start_task(task_type, name, f, budget, probe, band_width, port, vuln_params)

    @request_verify(require_params=['type'],
                    check_types=[CheckType('type',
                                           'int',
                                           [IPv6TaskModel.TYPE_QUERY_LIST, IPv6TaskModel.TYPE_STATISTICS])])
    def get(self, request: Request):
        typ: int = int(request.query_params.get('type'))

        if typ == IPv6TaskModel.TYPE_STATISTICS:
            return self.ipv6_manager.task_statistics()

        task_type = request.query_params.get('task_type', IPv6TaskModel.TYPE_ALL)
        task_name = request.query_params.get('task_name')
        c_page = request.query_params.get("pageNum")
        per_page = request.query_params.get("pageSize")

        if not CommonTools.require_not_none(c_page, per_page):
            return CustomResponse(Status.LACK_PARAM, msg='pageNum, pageSize 参数不能为空')

        return self.ipv6_manager.get_tasks_from_db(task_type, c_page, per_page, task_name)


'''
GET 获取状态/下载文件(3)
ipv6_task/name?type=?

DELETE 终止/删除任务(2)
 ipv6_task/name
'''


class IPv6TaskIdAPIView(APIView):

    def __init__(self):
        super(IPv6TaskIdAPIView, self).__init__()
        self.ipv6_manager = Singleton.get_ipv6_controller()

    @request_verify(require_params=['type'],
                    check_types=[CheckType('type', 'int')])
    def get(self, request: Request, pk):
        r_type: int = int(request.query_params.get('type'))

        match r_type:
            case IPv6TaskModel.TYPE_GET_STATE:
                return self.ipv6_manager.get_task_state(pk)
            case IPv6TaskModel.TYPE_GET_RESULT | IPv6TaskModel.TYPE_GET_ALL | IPv6TaskModel.TYPE_GET_UPLOAD:
                return self.ipv6_manager.get_task_result(pk, r_type)
            case IPv6TaskModel.TYPE_PARSE_RESULT:
                c_page = request.query_params.get("pageNum", "1")
                per_page = request.query_params.get("pageSize", "-1")

                if not CommonTools.require_not_none(c_page, per_page):
                    return CustomResponse(Status.LACK_PARAM, msg='pageNum或pageSize 参数不能为空')

                return self.ipv6_manager.parse_vuln_scan_result(pk, c_page, per_page)
            case IPv6TaskModel.TYPE_GET_LOG:
                return self.ipv6_manager.get_log(pk)
            case _:
                return CustomResponse(Status.PARAM_ERROR, msg='参数错误')

    @request_verify(require_params=['type'],
                    check_types=[CheckType('type', 'int')])
    def delete(self, request: Request, pk):
        d_type = int(request.query_params.get('type'))

        match d_type:
            case IPv6TaskModel.TYPE_TERMINATE:
                return self.ipv6_manager.stop_task(pk)
            case IPv6TaskModel.TYPE_DELETE:
                return self.ipv6_manager.delete_task(pk)
            case _:
                return CustomResponse(Status.PARAM_ERROR, msg='参数错误')


class ScriptAPIView(APIView):

    def __init__(self):
        super(ScriptAPIView, self).__init__()
        self.ipv6_manager = Singleton.get_ipv6_controller()

    def get(self, request: Request):
        page_num = int(request.query_params.get('pageNum', 1))
        page_size = int(request.query_params.get('pageSize', -1))
        return self.ipv6_manager.get_scripts(page_num, page_size)

    def post(self, request: Request):
        return self.ipv6_manager.check_scripts_update()


if __name__ == '__main__':
    print(IPv6TaskAPIView.as_view())
