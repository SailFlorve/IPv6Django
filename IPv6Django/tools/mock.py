from IPv6Django.constant import vuln_scripts
from IPv6Django.tools.common_tools import CommonTools


class IPv6TaskMocker:
    ports = [22, 135, 139, 445, 902, 912, 3389, 5357]
    services = ['ssh', 'msrpc', 'netbios-ssn', 'microsoft-ds', 'vmware-authd', 'vmware-authd', 'ms-wbt-server', 'llmnr']
    protocols = ['tcp', 'udp']

    @staticmethod
    def get_mock_command():
        return "ls"

    @staticmethod
    def mock_vuln_scan_data():
        data = []

        ips = ["2001:da8:200:9000::1", "2001:da8:200:9000::2", "2001:da8:200:9000::3", "2001:da8:200:9000::4"]

        for ip in ips:
            data.append(
                {
                    "ip": ip,
                    "ports": [
                        {
                            "protocol": CommonTools.choose_randomly(IPv6TaskMocker.protocols),
                            "portid": CommonTools.choose_randomly(IPv6TaskMocker.ports),
                            "state": "open",
                            "service": CommonTools.choose_randomly(IPv6TaskMocker.services),
                            "script": [{"id": t[0], "output": t[1]} for t in
                                       CommonTools.choose_randomly(vuln_scripts.script_list, 3)]
                        }
                    ],
                    "host_script": [{"id": t[0], "output": t[1]} for t in
                                    CommonTools.choose_randomly(vuln_scripts.script_list, 2)]
                }
            )

        return data


if __name__ == '__main__':
    print(IPv6TaskMocker.mock_vuln_scan_data())
