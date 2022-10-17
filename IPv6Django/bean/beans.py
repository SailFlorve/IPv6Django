import json
from dataclasses import dataclass


class BaseBean:
    def __init__(self):
        pass

    def to_dict(self):
        return self.__dict__

    def to_json(self):
        return json.dumps(self.__dict__, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str):
        return eval(cls.__name__)(**(json.loads(json_str)))


class StatusInternal(BaseBean):
    def __init__(self, status, message):
        super(StatusInternal, self).__init__()
        self.status = status
        self.__message_dict = {"title": message}
        self.message = str(self.__message_dict)

    def with_extra(self, extra: str) -> 'StatusInternal':
        """
        给message附加一些信息，返回自己
        """
        self.__message_dict["detail"] = extra
        self.message = str(self.__message_dict)
        return self


class Status(StatusInternal):
    OK = StatusInternal("10000", "成功")
    ERROR = StatusInternal("10001", "失败")
    LACK_PARAM = StatusInternal("10001", "缺少参数")
    FIELD_NOT_EXIST = StatusInternal("10002", "任务不存在")
    FIELD_EXIST = StatusInternal("10003", "任务已存在")
    NO_IPV6 = StatusInternal("10004", "没有可用的IPv6地址")
    PARAM_ERROR = StatusInternal("10005", "参数错误")
    TASK_NOT_FINISHED = StatusInternal("10006", "任务未完成")
    FILE_NOT_EXIST = StatusInternal("10007", "文件不存在")
    FILE_PARSE_ERROR = StatusInternal("10008", "文件解析错误")
    RESPONSE_ERROR = StatusInternal("10009", "响应错误")
    TASK_NOT_RUNNING = StatusInternal("10010", "任务未运行")
    LOCAL_IPV6 = StatusInternal("10011", "使用了本地IPv6，可能无法正常进行IPv6扫描")
    DELETE_ERROR = StatusInternal("10012", "删除失败")
    UPDATE_SCRIPTS_ERROR = StatusInternal("10012", "更新脚本失败")

    SERVER_EXCEPTION = StatusInternal("20000", "服务器异常")


@dataclass
class IPv6Params(BaseBean):
    ipv6: str = ""
    budget: int = 0
    probe: str = ""
    band_width: str = ""
    port: str = ""
    vuln_params: str = ""
    valid_upload_addr: int = 0  # 上传的地址文件中有效的地址数量


@dataclass
class IPv6Task(BaseBean):
    task_id: str
    task_name: str
    ipv6: str


@dataclass
class IPv6GenerateTaskResult(BaseBean):
    all_budget: int
    budget_left: int

    current_scan: int = 0  # zmap中的当前扫描进度
    all_scan: int = 0  # zmap中的总扫描进度
    current_cmd: str = ""  # 当前原生命令
    parse_cmd_1: str = ""  # 解析后的命令
    parse_cmd_2: str = ""  # 解析后的命令，如果上个变量不够用则用这个

    total_active: int = 0
    address_generated: int = 0
    hit_rate: float = 0

    generated_addr_example: str = ""  # 用于用json保存一部分生成的地址

    result_file_size = ""
    all_file_size = ""


@dataclass
class IPv6Statistics(BaseBean):
    all: int
    generate_num: int
    vuln_num: int
    generate_running: int
    generate_finished: int
    vuln_running: int
    vuln_finished: int


@dataclass
class PageInfo(BaseBean):
    pageNum: int  # 页码
    pageSize: int  # 每页数量
    total: int  # 总数


@dataclass
class UpdateInfo(BaseBean):
    update: int
    version: str


@dataclass
class VulnScript(BaseBean):
    name: str
    description: str


if __name__ == '__main__':
    pass
