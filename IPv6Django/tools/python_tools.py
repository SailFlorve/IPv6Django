import os
import pathlib
import socket
import subprocess
import sys
import urllib.request

from bs4 import BeautifulSoup

from IPv6Django.tools.ipv6_classification_tool import IPv6CIDRTool


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


def filter_cernet_ipv6():
    ip_path = pathlib.Path('/mnt/hgfs/Share/responsive-addresses.txt')
    new_path = pathlib.Path('/mnt/hgfs/Share/filter.txt')
    cidr_tool = IPv6CIDRTool()
    counter = 0
    with open(ip_path, 'r') as f:
        with open(new_path, 'w') as f2:
            for line in f.readlines():
                counter += 1
                ip = line
                if counter % 1000 == 0:
                    print(f'counter: {counter}')
                    print(sys.getsizeof(cidr_tool))
                    print(sys.getsizeof(f))
                if cidr_tool.get_isp(ip.strip()) == '中国教育和科研计算机网':
                    f2.write(ip)


def get_cve_scripts():
    uo = urllib.request.urlopen("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=ipv6")
    if uo.getcode() != 200:
        return
    bs4 = BeautifulSoup(uo.read())
    all_td = bs4.find('div', {'id': 'TableWithRules'}).find_all('td')

    vuln_name = ""
    vuln_des = ""
    scripts_list = []
    for i, td in enumerate(all_td):
        if i % 2 == 0:
            vuln_name = str(td.next.next).strip()
        else:
            vuln_des = str(td.next).strip()
            scripts_list.append((vuln_name, vuln_des))

    print(scripts_list)


if __name__ == '__main__':
    get_cve_scripts()
