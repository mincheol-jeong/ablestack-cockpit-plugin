'''
Copyright (c) 2021 ABLECLOUD Co. Ltd
설명 : 클러스터 설정 파일 cluster.json을 기준으로 /etc/hosts 파일을 세팅하는 기능
최초 작성일 : 2022. 08. 26
'''

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import sys
import os
import json
import socket

from ablestack import *
from sh import python3
from python_hosts import Hosts, HostsEntry

json_file_path = pluginpath+"/tools/properties/cluster.json"
hosts_file_path = "/etc/hosts"
def createArgumentParser():
    '''
    입력된 argument를 파싱하여 dictionary 처럼 사용하게 만들어 주는 parser를 생성하는 함수
    :return: argparse.ArgumentParser
    '''
    # 참조: https://docs.python.org/ko/3/library/argparse.html
    # 프로그램 설명
    parser = argparse.ArgumentParser(description='클러스터 설정 파일 cluster.json을 기준으로 /etc/hosts 파일을 세팅하는 프로그램',
                                        epilog='copyrightⓒ 2021 All rights reserved by ABLECLOUD™',
                                        usage='%(prog)s arguments')

    # 인자 추가: https://docs.python.org/ko/3/library/argparse.html#the-add-argument-method
    parser.add_argument('action', choices=['hostOnly','withScvm','withCcvm'], help='choose one of the actions')
    parser.add_argument('-t', '--type', metavar='[OS Type]', type=str, help='input Value to OS Type')
    # output 민감도 추가(v갯수에 따라 output및 log가 많아짐):
    parser.add_argument('-v', '--verbose', action='count', default=0, help='increase output verbosity')

    # flag 추가(샘플임, 테스트용으로 json이 아닌 plain text로 출력하는 플래그 역할)
    parser.add_argument('-H', '--Human', action='store_const', dest='flag_readerble', const=True, help='Human readable')

    # Version 추가
    parser.add_argument('-V', '--Version', action='version', version='%(prog)s 1.0')

    return parser

def openClusterJson():
    try:
        with open(json_file_path, 'r') as json_file:
            ret = json.load(json_file)
    except Exception as e:
        ret = createReturn(code=500, val='cluster.json read error')
        print ('EXCEPTION : ',e)

    return ret
json_data = openClusterJson()
os_type = json_data["clusterConfig"]["type"]

# 파라미터로 받은 json 값으로 cluster_config.py 무조건 바꾸는 함수 (동일한 값이 있으면 변경, 없으면 추가)
def changeHosts(args):
    try:
        # 호스트 파일 초기화
        if args.type == "ablestack-vm":

            with open(hosts_file_path, "r") as file:
                lines = file.readlines()

            with open(hosts_file_path, "w") as file:
                file.writelines(lines[:2])

        hostname = socket.gethostname()
        my_hosts = Hosts(path=hosts_file_path)
        hosts_arry = []
        if json_data["clusterConfig"]["ccvm"]["ip"] != '':

            my_hosts.remove_all_matching(address=json_data["clusterConfig"]["ccvm"]["ip"])
            my_hosts.remove_all_matching(name="ccvm-mngt")
            my_hosts.remove_all_matching(name="ccvm")

            entry = HostsEntry(entry_type='ipv4', address=json_data["clusterConfig"]["ccvm"]["ip"], names=["ccvm-mngt", "ccvm"])
            my_hosts.add([entry])

        for f_val in json_data["clusterConfig"]["hosts"]:
            json_ips = {}
            hostname_arry = []
            if args.type == "PowerFlex":
                # PowerFlex용 SCVM 호스트 파일
                my_hosts.remove_all_matching(address=f_val["ablecube"])
                my_hosts.remove_all_matching(address=f_val["scvmMngt"])
                my_hosts.remove_all_matching(address=f_val["ablecubePn"])
                my_hosts.remove_all_matching(address=f_val["scvm"])
                my_hosts.remove_all_matching(address=f_val["scvmCn"])
                # PowerFlex용 SCVM 호스트 파일
                my_hosts.remove_all_matching(name=f_val["hostname"])
                my_hosts.remove_all_matching(name="scvm"+f_val["index"])
                my_hosts.remove_all_matching(name="pn-"+"ablecube"+f_val["index"])
                my_hosts.remove_all_matching(name="pn-"+"scvm"+f_val["index"])
                my_hosts.remove_all_matching(name="cn-"+"scvm"+f_val["index"])

            elif args.type == "ablestack-vm":
                my_hosts.remove_all_matching(name=f_val["hostname"])
                my_hosts.remove_all_matching(name=f_val["ablecube"])

            else:
                # hosts 파일 내용 ip로 제거
                my_hosts.remove_all_matching(address=f_val["ablecube"])
                my_hosts.remove_all_matching(address=f_val["scvmMngt"])
                my_hosts.remove_all_matching(address=f_val["ablecubePn"])
                my_hosts.remove_all_matching(address=f_val["scvm"])
                my_hosts.remove_all_matching(address=f_val["scvmCn"])
                # hosts 파일 내용 도메인으로 제거
                my_hosts.remove_all_matching(name=f_val["hostname"])
                my_hosts.remove_all_matching(name="scvm"+f_val["index"]+"-mngt")
                my_hosts.remove_all_matching(name="pn-"+"ablecube"+f_val["index"])
                my_hosts.remove_all_matching(name="scvm"+f_val["index"])
                my_hosts.remove_all_matching(name="cn-"+"scvm"+f_val["index"])

            if hostname == f_val["hostname"]:

                if args.type == "PowerFlex":
                    # PowerFlex용 SCVM 호스트 파일
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecube"], names=[f_val["hostname"], 'ablecube'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmMngt"], names=["scvm"+f_val["index"], 'scvm'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecubePn"], names=["pn-"+"ablecube"+f_val["index"], 'pn-ablecube'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvm"], names=["pn-"+"scvm"+f_val["index"], 'pn-scvm'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmCn"], names=["cn-"+"scvm"+f_val["index"], 'cn-scvm'])
                    my_hosts.add([entry])
                elif args.type == "ablestack-vm":
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecube"], names=[f_val["hostname"], 'ablecube'])
                    my_hosts.add([entry])
                else:
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecube"], names=[f_val["hostname"], 'ablecube'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmMngt"], names=["scvm"+f_val["index"]+"-mngt", 'scvm-mngt'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecubePn"], names=["pn-"+"ablecube"+f_val["index"], 'pn-ablecube'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvm"], names=["scvm"+f_val["index"], 'scvm'])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmCn"], names=["cn-"+"scvm"+f_val["index"], 'cn-scvm'])
                    my_hosts.add([entry])

            else:
                if args.type == "PowerFlex":
                    # PowerFlex용 SCVM 호스트 파일
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecube"], names=[f_val["hostname"]])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmMngt"], names=["scvm"+f_val["index"]])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecubePn"], names=["pn-"+"ablecube"+f_val["index"]])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvm"], names=["pn-"+"scvm"+f_val["index"]])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmCn"], names=["cn-"+"scvm"+f_val["index"]])
                    my_hosts.add([entry])
                elif args.type == "ablestack-vm":
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecube"], names=[f_val["hostname"]])
                    my_hosts.add([entry])
                else:
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecube"], names=[f_val["hostname"]])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmMngt"], names=["scvm"+f_val["index"]+"-mngt"])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["ablecubePn"], names=["pn-"+"ablecube"+f_val["index"]])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvm"], names=["scvm"+f_val["index"]])
                    my_hosts.add([entry])
                    entry = HostsEntry(entry_type='ipv4', address=f_val["scvmCn"], names=["cn-"+"scvm"+f_val["index"]])
                    my_hosts.add([entry])

        my_hosts.write()

        python3(pluginpath+'/python/host/ssh-scan.py')

        return createReturn(code=200, val="hosts file config success.")
    except Exception as e:
        # 결과값 리턴
        return createReturn(code=500, val="Please check the \"cluster.json\" file. : "+e)

def hostOnly(args):
    ret = changeHosts(args)
    return ret

def withScvm(args):
    ret = changeHosts(args)
    if os_type == "ABLESTACK-HCI":
        os.system("scp -q -o StrictHostKeyChecking=no " + hosts_file_path + " root@scvm-mngt:/etc/hosts")
    # os.system("scp -q "+ hosts_file_path +" root@scvm-mngt:/etc/hosts")
    return ret

def withCcvm(args):
    ret = changeHosts(args)
    os.system("scp -q -o StrictHostKeyChecking=no " + hosts_file_path + " root@ccvm-mngt:/etc/hosts")
    # os.system("scp -q "+ hosts_file_path +" root@ccvm-mngt:/etc/hosts")
    return ret

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # parser 생성
    parser = createArgumentParser()
    # input 파싱
    args = parser.parse_args()

    verbose = (5 - args.verbose) * 10

    # 로깅을 위한 logger 생성, 모든 인자에 default 인자가 있음.
    logger = createLogger(verbosity=logging.CRITICAL, file_log_level=logging.ERROR, log_file='test.log')

    # 실제 로직 부분 호출 및 결과 출력
    if args.action == 'hostOnly':
        ret = hostOnly(args)
        print(ret)
    elif args.action == 'withScvm':
        ret = withScvm(args)
        print(ret)
    elif args.action == 'withCcvm':
        ret = withCcvm(args)
        print(ret)
