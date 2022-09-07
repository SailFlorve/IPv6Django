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


@dataclass
class Status(BaseBean):
    OK = "10000"
    ERROR = "10001"
    LACK_PARAM = "10001"
    FIELD_NOT_EXIST = "10002"
    FIELD_EXIST = "10003"
    NO_IPV6 = "10004"
    PARAM_ERROR = "10005"
    TASK_NOT_FINISHED = "10006"
    FILE_NOT_EXIST = "10007"
    FILE_PARSE_ERROR = "10008"
    RESPONSE_ERROR = "10009"
    TASK_NOT_RUNNING = "10010"
    SERVER_EXCEPTION = "20000"

    status: str
    message: str


@dataclass
class IPv6Params(BaseBean):
    ipv6: str = ""
    budget: int = 0
    probe: str = ""
    band_width: str = ""
    port: str = ""
    vuln_params: str = ""
    valid_upload_addr: int = 0


@dataclass
class IPv6Task(BaseBean):
    task_id: str
    task_name: str


@dataclass
class IPv6GenerateTaskResult(BaseBean):
    all_budget: int
    budget_left: int

    current_scan: int = 0
    all_scan: int = 0
    current_cmd: str = ""
    parse_cmd_1: str = ""
    parse_cmd_2: str = ""

    total_active: int = 0
    address_generated: int = 0
    hit_rate: float = 0

    generated_addr_example: str = ""


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


if __name__ == '__main__':
    pass
