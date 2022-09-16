import pathlib
from os import PathLike

from bs4 import BeautifulSoup

from IPv6Django.ipv6_extend.constant import Constant
from IPv6Django.tools.common_tools import Logger, CommonTools
from IPv6Django.tools.process_executor import ProcessExecutor


class IPv6VulnerabilityScanner:
    def __init__(self, origin_file_path_str: str | PathLike[str], work_path_str: str | PathLike[str], options_str: str):
        self.processExecutor = ProcessExecutor()
        self.origin_file_path = pathlib.Path(origin_file_path_str)
        self.work_path = pathlib.Path(work_path_str)

        self.scan_res_path = CommonTools.get_work_result_path_by_work_path(self.work_path) / Constant.SCAN_RES_NAME

        self.options_str = options_str

        self.on_finish_callback = None

    def set_on_finish_callback(self, callback):
        self.on_finish_callback = callback

    def scan(self):
        def finish_callback(exit_code):
            Logger.log_to_file("scan finished", path=self.work_path)
            if self.on_finish_callback is not None:
                self.on_finish_callback(exit_code)

        nmap_cmd = f"nmap -6 -iL {str(self.origin_file_path)} " \
                   f"-oA {self.scan_res_path} "

        if self.options_str is None or self.options_str == "":
            nmap_cmd += f"--script=vuln -Pn -n -v -v "
        else:
            nmap_cmd += self.options_str

        self.processExecutor.execute(nmap_cmd, finished_callback=finish_callback)

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
