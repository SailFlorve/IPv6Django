import pathlib
import threading
from os import PathLike
from typing.io import TextIO

from IPv6Django.constant.constant import Constant
from IPv6Django.tools.common_tools import Logger
from IPv6Django.tools.ipv6_classification_tool import IPv6ASNTool, IPv6StatisticsTool


class IPv6MultiLevelClassification:

    def __init__(self, work_path: str | PathLike[str], addr_path: str | PathLike[str] = pathlib.Path()):
        self.work_path = pathlib.Path(work_path)
        self.addr_path = pathlib.Path(addr_path)
        self.output_path = self.work_path / Constant.PREPROCESS_DIR / Constant.MULTI_LEVEL_CLASSIFICATION_NAME

        self.asn_tool = IPv6ASNTool()
        self.statistics_tool = IPv6StatisticsTool()
        self.thread = threading.Thread(target=self.__multi_level_classification_internal)

    def multi_level_classification(self):
        Logger.log_to_file("start multi level classification", path=self.work_path)
        self.thread.start()

    def __multi_level_classification_internal(self):
        with open(self.addr_path, 'r') as f1:
            with open(self.output_path, 'w+') as f2:
                self.__format_write(f2, "IPv6", "ASN", "BGP_PREFIX", "IID_LOG_Q")
                for line in f1.readlines():
                    addr = line.strip()
                    asn_num, bgp_prefix = self.asn_tool.get_asn_bgp(addr)
                    iid_log_q = self.statistics_tool.get_iid_log_q(addr)
                    self.__format_write(f2, addr, asn_num, bgp_prefix, iid_log_q)
        Logger.log_to_file("multi level classification finished", path=self.work_path)

    @staticmethod
    def __format_write(f: "TextIO", ipv6: str, asn: str, bgp: str, iid_log_q: str):
        f.write('{0:<40}'.format(ipv6))
        f.write('{0:<10}'.format(asn))
        f.write('{0:<25}'.format(bgp))
        f.write('{0:<20}'.format(iid_log_q))
        f.write("\n")


if __name__ == '__main__':
    level_classification = IPv6MultiLevelClassification(
        '/root/PyCharmProjects/IPv6Django/result/G-de1c61d6-506f-11ed-8052-3b0b0e9846f1',
        '/root/PyCharmProjects/IPv6Django/upload/G-de1c61d6-506f-11ed-8052-3b0b0e9846f1/active_2w')

    level_classification.multi_level_classification()
