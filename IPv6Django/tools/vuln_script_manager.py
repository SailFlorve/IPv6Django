import urllib.request

from bs4 import BeautifulSoup

from IPv6Django.constant import vuln_scripts
from IPv6Django.models import VulnScriptModel


class VulnDatabaseManager:
    def __init__(self):
        pass

    @staticmethod
    def init_db_if_empty():
        if len(VulnScriptModel.objects.all()) != 0:
            return

        scripts_local = vuln_scripts.script_list
        for script_tuple in scripts_local:
            model = VulnScriptModel(name=script_tuple[0], description=script_tuple[1])
            model.save()

    @staticmethod
    def load_scripts() -> list[VulnScriptModel]:
        urlopen = urllib.request.urlopen("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=ipv6", timeout=15)
        ret_code = urlopen.getcode()
        if ret_code != 200:
            raise ConnectionError(f'请求更新错误: {ret_code}')

        bs4 = BeautifulSoup(urlopen.read())
        all_td = bs4.find('div', {'id': 'TableWithRules'}).find_all('td')

        vuln_name = ""

        scripts_list: list[VulnScriptModel] = []
        for i, td in enumerate(all_td):
            if i % 2 == 0:
                vuln_name = str(td.next.next).strip()
            else:
                vuln_des = str(td.next).strip()
                scripts_list.append(VulnScriptModel(name=vuln_name, description=vuln_des))

        return scripts_list
