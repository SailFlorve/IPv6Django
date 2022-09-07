import os
import socket


def get_ipv6():
    output = os.popen("ifconfig").read()
    print(output)


def get_ipv61():
    host_ipv6 = []
    ips = socket.getaddrinfo(socket.gethostname(), 80)

    for ip in ips:
        print(ip[4])
        if ip[4][0].find(":") != -1 and not ip[4][0].startswith('fe80'):
            # 2408 中国联通
            # 2409 中国移动
            # 240e 中国电信
            host_ipv6.append(ip[4][0])

    if len(host_ipv6) == 0:
        # return ""
        return 0
    else:
        return host_ipv6[0]


get_ipv6()
print(get_ipv61())
