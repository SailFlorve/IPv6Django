from IPv6Django.constant import vuln_scripts
from IPv6Django.tools.common_tools import RandomTool


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

        ips = [f"2001:da8:200:9000::{RandomTool.generate_random_num_seq(0, 10, 4)}",
               f"2001:da8:200:9000::{RandomTool.generate_random_num_seq(0, 10, 4)}",
               f"2001:da8:200:9000::{RandomTool.generate_random_num_seq(0, 10, 4)}",
               f"2001:da8:200:9000::{RandomTool.generate_random_num_seq(0, 10, 4)}"]

        for ip in ips:
            port_list = []
            port_num = RandomTool.rand_int(1, 4)
            print("port_num",port_num)
            for i in range(port_num):
                script_num = RandomTool.rand_int(2, 4)
                port_list.append(
                    {
                        "protocol": RandomTool.choose_randomly(IPv6TaskMocker.protocols),
                        "portid": RandomTool.choose_randomly(IPv6TaskMocker.ports),
                        "state": "open",
                        "service": RandomTool.choose_randomly(IPv6TaskMocker.services),
                        "script": [{"id": t[0], "output": t[1]} for t in
                                   RandomTool.choose_randomly(vuln_scripts.script_list, script_num)]
                    }
                )

            host_script_num = RandomTool.rand_int(2, 4)
            data.append(
                {
                    "ip": ip,
                    "ports": port_list,
                    "host_script": [{"id": t[0], "output": t[1]} for t in
                                    RandomTool.choose_randomly(vuln_scripts.script_list, host_script_num)]
                }
            )

        return data


if __name__ == '__main__':
    print(IPv6TaskMocker.mock_vuln_scan_data())
