import os
import pathlib
import socket
import subprocess
import urllib.request

from bs4 import BeautifulSoup

from IPv6Django.tools.process_executor import ProcessExecutor


def get_ipv6():
    try:
        return get_ipv6_cmd()
    except subprocess.CalledProcessError:
        return get_ipv6_socket()


def get_ipv6_cmd():
    ipv6 = subprocess.check_output(
        r"ip -6 addr | grep inet6 | awk -F '[ \t]+|/' '{print $3}' | grep -v ^::1 | grep -v ^fe80", shell=True,
        encoding="utf-8")
    return ipv6.split("\n")[0]


def get_ipv6_socket():
    host_ipv6 = []
    ips = socket.getaddrinfo(socket.gethostname(), 80)

    for ip in ips:
        print(ip[4])
        if ip[4][0].find(":") != -1:
            # 2408 中国联通
            # 2409 中国移动
            # 240e 中国电信
            host_ipv6.append(ip[4][0])

    if len(host_ipv6) == 0:
        return ""
        # if settings.DEBUG:
        #     return '2001:da8:100e:5000::1:59af'
        # else:
        #     return '2001:da8:100e:5000::1:59af'
    else:
        all_local_ipv6 = True
        global_ipv6: str = ""
        for ipv6 in host_ipv6:
            if not ipv6.startswith("fe80"):
                global_ipv6 = ipv6
                all_local_ipv6 = False
        return host_ipv6[0] if all_local_ipv6 else global_ipv6


def _get_subdir_size_bydu(dir, depth=0):
    # 获取以及目录下的文件夹大小
    res_list = os.popen(f'du {dir} -h --max-depth={depth}')

    res_list = [x.split('\t') for x in res_list]

    subdir_sizes = {
        x[1].strip('\n'): x[0]
        for x in res_list
    }
    return subdir_sizes


def get_scripts():
    result_dict = {}
    urlopen = urllib.request.urlopen("https://nmap.org/nsedoc/categories/vuln.html")
    bs4 = BeautifulSoup(urlopen.read())
    # bs4.findAll('dt')[0].next.next
    # bs4.findAll('dt')[0].nextSibling.next.next.next
    all_dt = bs4.findAll('dt')
    for dt in all_dt:
        vuln_name = str(dt.next.next).strip()
        vuln_des = str(dt.nextSibling.next.next.next).strip()
        result_dict[vuln_name] = vuln_des
    return result_dict


if __name__ == '__main__':
    print(get_scripts())
