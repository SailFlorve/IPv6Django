import math
import pathlib
from ipaddress import ip_network, ip_address

import pyasn


class IPv6ASNTool:
    def __init__(self):
        lib_path = pathlib.Path('ipv6db/asn/asn_v6.dat')
        if not lib_path.exists():
            lib_path = pathlib.Path(__file__).parent.parent.parent / lib_path

        self.asn_db = pyasn.pyasn(str(lib_path.resolve()))

    def get_asn_bgp(self, ipv6) -> (int, str):
        asn_num, prefix = self.asn_db.lookup(ipv6)
        if asn_num is None:
            asn_num = 0
        if prefix is None:
            prefix = "0/0"
        return asn_num, prefix


class IPv6CIDRTool:
    def __init__(self):
        lib_path = pathlib.Path('ipv6db/cidr')
        if not lib_path.exists():
            lib_path = pathlib.Path(__file__).parent.parent.parent / lib_path

        self.cidr_dict: dict[str, dict[str, str]] = {}  # {prefix: {cidr: isp}}
        self.isp_dict: dict[str, str] = {}  # {isp: cidr}

        for cidr_path in lib_path.glob('*'):
            if cidr_path.name == 'china6.txt':
                continue
            self.__add_cidr_to_dict(cidr_path)

        self.__add_cidr_to_dict(lib_path / 'china6.txt')

    def __add_cidr_to_dict(self, cidr_path):
        with open(cidr_path, 'r') as f:
            net_name = ""
            for i, line in enumerate(f.readlines()):
                content = line.strip()
                if i == 0:
                    net_name = content
                    continue

                prefix = self.__get_prefix(content)
                if prefix not in self.cidr_dict:
                    self.cidr_dict[prefix] = {}

                if content not in self.cidr_dict[prefix]:
                    self.cidr_dict[prefix][content] = net_name
                else:
                    pass
                    # print(f"Duplicate CIDR: {net_name} {content}")

    @staticmethod
    def __get_prefix(ipv6: str):
        return ipv6[0:7]

    def get_isp(self, ipv6: str) -> str:
        result = self.__query_internal(ipv6)[1]
        if result is None:
            result = '其他'
        return result

    def get_cidr(self, ipv6: str) -> str:
        result = self.__query_internal(ipv6)[0]
        if result is None:
            result = '0/0'
        return result

    def __query_internal(self, ipv6: str) -> (str, str):
        idx = 0
        prefix = self.__get_prefix(ipv6)
        if prefix not in self.cidr_dict:
            return None, None

        for cidr, isp in self.cidr_dict[prefix].items():
            idx += 1
            if ip_address(ipv6) in ip_network(cidr):
                return cidr, isp

        return None, None


class IPv6StatisticsTool:
    def init(self):
        pass

    @staticmethod
    def get_iid_log_q(ipv6: str):
        ipv6_exploded = ip_address(ipv6).exploded.replace(':', '')
        iid = ipv6_exploded[16:32]
        iid_set = set(iid)
        type_num = 0
        for b in iid_set:
            type_num = max(iid.count(b), type_num)
        return math.log(type_num / len(iid_set), 16) + 1


if __name__ == '__main__':
    print(ip_address('240c:6::0').exploded)
    print(IPv6StatisticsTool.get_iid_log_q('240c:6:0:0:0123:4567:89ab:cdef'))
    exit(5)

    t = IPv6CIDRTool()
    print(t.get_isp('2001:da8:e024:200::1'))

    tool = IPv6ASNTool()
    print(tool.get_asn_bgp('240c:6:0:0:ffff:ffff:ffff:0001'))
    with open('/mnt/hgfs/Share/cernet_2w', 'r') as f:
        for line in f.readlines():
            print(tool.get_asn_bgp(line.strip()))
            break
