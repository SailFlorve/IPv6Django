import json
import pathlib
from os import PathLike

from bs4 import BeautifulSoup

from IPv6Django.constant.constant import Constant
from IPv6Django.ipv6_task.ipv6_task_base import IPv6TaskBase
from IPv6Django.tools.common_tools import Logger, CommonTools


class IPv6VulnerabilityScanner(IPv6TaskBase):
    def __init__(self, origin_file_path_str: str | PathLike[str], work_path_str: str | PathLike[str], options_str: str):
        super(IPv6VulnerabilityScanner, self).__init__(work_path_str, origin_file_path_str)

        self.scan_res_path = CommonTools.get_work_result_path_by_work_path(self.work_path) / Constant.SCAN_RES_NAME

        self.options_str = options_str

    def run(self):
        self.scan()

    def scan(self):
        def finish_callback(exit_code):
            try:
                # 解析xml为json
                result_xml_path = CommonTools.get_work_result_path_by_work_path(
                    self.work_path) / (Constant.SCAN_RES_NAME + ".xml")
                nmap_parse_result = IPv6VulnerabilityScanner.parse_xml(result_xml_path)
                result_json_path = CommonTools.get_work_result_path_by_work_path(
                    self.work_path) / (Constant.SCAN_RES_NAME + '.json')
                result_json_path.write_text(json.dumps(nmap_parse_result))

            except Exception as e:
                Logger.log_to_file(str(e), path=self.work_path)

            Logger.log_to_file("Scan finished", path=self.work_path)
            if self.finished_callback is not None:
                self.finished_callback(exit_code)

        nmap_cmd = f"nmap -6 -iL {str(self.origin_file_path)} " \
                   f"-oA {self.scan_res_path} "

        if self.options_str is None or self.options_str == "":
            nmap_cmd += f"--script=vuln -Pn -n -v -v "  # -n 禁止dns解析 -Pn 跳过Ping扫描
        else:
            nmap_cmd += self.options_str

        Logger.log_to_file(nmap_cmd, path=self.work_path)
        self.process_executor.execute(nmap_cmd, finished_callback=finish_callback)

    @staticmethod
    def parse_xml(xml_path: pathlib.Path):
        parse_result = []
        soup = BeautifulSoup(xml_path.read_text(), 'xml')
        for host in soup.find_all('host'):
            if host.status['state'] == 'up':
                ip = host.address['addr']
                ports = []
                host_script = []
                for port in host.ports.find_all('port'):
                    d = {'protocol': port['protocol'], 'portid': port['portid'], 'state': port.state['state'],
                         'service': port.service['name'], 'script': []}

                    for script in port.find_all('script'):
                        d['script'].append({"id": script['id'], "output": script['output']})

                    ports.append(d)

                for hs in host.find_all('hostscript'):
                    for script in hs.find_all('script'):
                        host_script.append({"id": script['id'], "output": script['output']})

                parse_result.append(
                    {'ip': ip,
                     'state': host.status['state'],
                     'ports': ports,
                     'host_script': host_script,

                     }
                )
            else:
                parse_result.append(
                    {
                        'ip': host.address['addr'],
                        'state': host.status['state'],
                    }
                )
        return parse_result
