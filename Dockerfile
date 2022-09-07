FROM python:3.10
ENV PYTHONUNBUFFERED 1

RUN mkdir /usr/src/IPv6Django -p
WORKDIR /usr/src/IPv6Django
ADD requirements.txt /usr/src/IPv6Django
ADD ./zmap-master /usr/src/IPv6Django/zmap-master
ADD sources.list /etc/apt/ 

# 添加 pip 清华镜像源
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN ls \
    && apt-get upgrade \
    && apt-get update \
    && apt-get install -y aptitude \
    && apt-get install -y build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev \
    && cd zmap-master \
    && cmake . \
    && make -j4 \
    && make install \
    && apt-get install -y nmap \
    && cd ../ \
    && rm -rf zmap-master \
    && rm -rf upload \
    && rm -rf result 