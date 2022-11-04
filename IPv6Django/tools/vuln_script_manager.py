import urllib.request

from bs4 import BeautifulSoup

from IPv6Django.constant import vuln_scripts
from IPv6Django.models import VulnScriptModel


class VulnScriptManager:
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
        result_list = []
        urlopen = urllib.request.urlopen("https://nmap.org/nsedoc/categories/vuln.html")
        bs4 = BeautifulSoup(urlopen.read(), 'lxml')
        # bs4.findAll('dt')[0].next.next
        # bs4.findAll('dt')[0].nextSibling.next.next.next
        all_dt = bs4.findAll('dt')
        for dt in all_dt:
            vuln_name = str(dt.next.next).strip()
            vuln_des = str(dt.nextSibling.next.next.next).strip()
            result_list.append(VulnScriptModel(vuln_name, vuln_des))
        return result_list
