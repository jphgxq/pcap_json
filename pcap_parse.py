#!/usr/bin/env python
#coding:utf-8

import struct
import operator
import dpkt
import datetime
import os
import shutil
import re
import hashlib
import json
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
try:
    import scapy.all as scapy
except ImportError:
    import scapy
'''
    定义全局变量
'''
domain_name_combine = ''
#临时存放数据的列表
request_serial_assist = []
response_serial_assist = []
request_port_assist = []
response_port_assist = []
request_datalist = []
response_datalist = []
data_assist = []

#输入需要解析的pcap文件路径
pcapfile = 'netdata.pcap'
#定义需要存储全部结果的路径并进行检测，若目录存在则删除，不存在则创建
all_path = pcapfile + 'result/'

if os.path.exists(all_path):
    shutil.rmtree(all_path)
    os.makedirs(all_path)
else:
    os.makedirs(all_path)

#创建request.txt文件存储http中request原始报文
request_txt_string = all_path + 'request.txt'
#创建response.txt文件存储http中response原始报文
response_txt_string = all_path + 'response.txt'

log = all_path + 'logcat'
log_file = open(log, 'wb')

#将所有的http会话拆分为两部分，request和response，并分别存储在对应的txt文件中
request_txt = open(request_txt_string, 'wb')
response_txt = open(response_txt_string, 'wb')

#定义存储的目录名,http
file_path = all_path + 'http/'
content_path = all_path + 'http/http_content/'

#文件存在则覆盖
if os.path.exists(file_path):
    shutil.rmtree(file_path)
    os.makedirs(file_path)
else:
    os.makedirs(file_path)

if os.path.exists(content_path):
    shutil.rmtree(content_path)
    os.makedirs(content_path)
else:
    os.makedirs(content_path)

'''
    定义全局变量
'''

class http:
    #定义http数据包的序列号，数据， 数据包序号，数据包长度， 源端口，目标端口，会话端口号
    def __init__(self, serial, datas, packet_num, data_len, sport, dport, conversation_port, time_http):
        self.serial = serial
        self.datas = datas
        self.packet_num = packet_num
        self.data_len = data_len
        self.sport = sport
        self.dport = dport
        self.conversation_port = conversation_port
        self.time_http = time_http
    def classify_data_packet(self):
        #分割不同方向的会话
        if self.sport == 80:
            #判断端口号的列表中是否有数据
            if not len(response_port_assist):
                response_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                response_datalist.append(conversationdata)
            if self.conversation_port in response_port_assist:
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                response_datalist.append(conversationdata)
            elif self.conversation_port not in response_port_assist:
                sort_by_num(response_datalist,'serialnum')
                printhttp_finaldata(response_datalist)
                response_txt.write('='*5 + '\n')
                del(response_datalist[0:len(response_datalist)])
                response_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                response_datalist.append(conversationdata)
        elif self.dport == 80:
            if not len(request_port_assist):
                request_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                request_datalist.append(conversationdata)
            if self.conversation_port in request_port_assist:
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                request_datalist.append(conversationdata)
            elif self.conversation_port not in request_port_assist:
                sort_by_num(request_datalist, 'serialnum')
                printhttp_finaldata(request_datalist)
                request_txt.write('='*5 + '\n')
                del(request_datalist[0:len(request_datalist)])
                request_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                request_datalist.append(conversationdata)

class httpconversation:
    def __init__(self,serialnum,finaldata,conversation_port,sport,dport,packet_num):
        self.serialnum = serialnum
        self.finaldata = finaldata
        self.conversation_port = conversation_port
        self.sport = sport
        self.dport = dport
        self.packet_num = packet_num
    def print_http_data(self):
        #response报文
        if self.sport == 80:
            #判断序列号列表中是否有数据
            if not len(response_serial_assist):
                response_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)
            elif self.serialnum in response_serial_assist:
                data_assist.append(self.finaldata)
            elif self.serialnum not in response_serial_assist:
                responsemax_flag = max(data_assist)[0:4]
                #去除不规范的数据
                if responsemax_flag == 'GET ' or responsemax_flag == 'POST':
                    print 'already delete useless information'
                elif max(data_assist) != '\r\n':
                    response_txt.write(max(data_assist))
                del(data_assist[0:len(data_assist)])
                response_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)
        elif self.dport == 80:
            if not len(request_serial_assist):
                request_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)
            elif self.serialnum in request_serial_assist:
                data_assist.append(self.finaldata)
            elif self.serialnum not in request_serial_assist:
                #与相应报文的判断相反
                requestmax_flag = max(data_assist)[0:4]
                if requestmax_flag == 'GET ' or requestmax_flag == 'POST':
                    request_txt.write(max(data_assist))
                del(data_assist[0:len(data_assist)])
                request_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)

def  pcap_parse(pcapfile):
    global domain_name_combine
    fpcap = open(pcapfile, 'rb')
    f = open(pcapfile)

    #dpkt解析pcap文件结果存储在pcap变量中
    pcap = dpkt.pcap.Reader(f)

    #读取pcap文件存储为字符串
    string_data = fpcap.read()

    times = []

    #使用dpkt获取每个数据包的时间戳，并存储在times列表中
    for ts, buf in pcap:
        timestr = datetime.datetime.fromtimestamp(ts)
        times.append(str(timestr))

    #读取解析pcap文件中的数据包，scapy模块
    packets = scapy.rdpcap(pcapfile)
    #统计数据包数量
    packet_num = 0
    #统计ip数据包数量
    ip_num = 0
    #统计TCP数据包数量
    tcp_num = 0
    #统计http数据包数量
    http_num = 0
    #统计udp数据包数量
    udp_num = 0
    #数据包中的源mac和目标mac地址存放在列表中
    smacs = []
    dmacs = []
    #数据包中的源ip和目标ip地址存放在列表中
    sips = []
    dips = []

    #将对应字段的解析结果以字典的形式存储
    pcap_packet_header = {}
    pcap_packet_mac = {}
    pcap_packet_ip = {}
    pcap_packet_tcp = {}
    pcap_packet_udp = {}
    pcap_packet_dns = {}

    #保存json格式的字典
    tcp = {}
    tcp_data = {}
    udp = {}
    udp_data = {}

    #定义各个部分的起始位置
    #起始packet数据包头位置，跳过pcap文件头
    i = 24
    #起始数据链路头位置
    j = 40
    #起始IP头位置
    k = 54
    #起始tcp或udp位置
    l = 74

    #存放http数据包中包含数据的部分
    http_old_data = []

    #处理数据包中的源mac地址、目标mac地址、源IP地址、目标IP地址，并存储在上述定义的列表中
    for p in packets:
        for Ethernet in p.fields_desc:
            if Ethernet.name == 'src':
                smacs.append(p.src)
            elif Ethernet.name == 'dst':
                dmacs.append(p.dst)
            elif Ethernet.name == 'type':
                Ethernet_type = p.type
                if Ethernet_type == 2048:
                    for IP in p.payload.fields_desc:
                        if IP.name == 'src':
                            IPsrcvalue = p.payload.getfieldval(IP.name)
                            sips.append(IPsrcvalue)
                        elif IP.name == 'dst':
                            IPdstvalue = p.payload.getfieldval(IP.name)
                            dips.append(IPdstvalue)

    #进行pcap文件的解析
    while(i<len(string_data)):

        #数据包长度
        pcap_packet_header['caplen'] = string_data[i+8:i+12]
        packet_caplen = struct.unpack('I', pcap_packet_header['caplen'])[0]

        #实际数据包长度，同时输出数据包时间戳
        pcap_packet_header['len'] = string_data[i+12:i+16]
        packet_len = struct.unpack('I', pcap_packet_header['len'])[0]

        #解析数据链路头类型
        pcap_packet_mac['type'] = string_data[j+12:j+14]

        #判断是否是IP包
        if pcap_packet_mac['type'] == '\x08\x00':
            timestamp = times[packet_num]

            #总长度
            pcap_packet_ip['totallen'] = string_data[k+2:k+4]
            pcap_packet_ip['totallen'] = pcap_packet_ip['totallen'][1:2] + pcap_packet_ip['totallen'][0:1]
            total_len = struct.unpack('H', pcap_packet_ip['totallen'])[0]

            pcap_packet_ip['proto'] = string_data[k+9:k+10]
            ip_proto = struct.unpack('B', pcap_packet_ip['proto'])[0]
            sip = sips[ip_num]
            dip = dips[ip_num]
            ip_num += 1

            #判断是否是TCP包
            if ip_proto == 6:
                tcp['uid'] = 10097
                tcp['timestamp'] = timestamp
                tcp['typeid'] = 786433
                tcp['class'] = 'null'
                tcp['parameters'] = 'null'
                tcp['return'] = 'null'
                tcp['stackTrace'] = 'null'
                tcp_num += 1

                pcap_packet_tcp['sport'] = string_data[l:l+2]
                pcap_packet_tcp['dport'] = string_data[l+2:l+4]
                pcap_packet_tcp['sport'] = pcap_packet_tcp['sport'][1:2]+pcap_packet_tcp['sport'][0:1]
                pcap_packet_tcp['dport'] = pcap_packet_tcp['dport'][1:2]+pcap_packet_tcp['dport'][0:1]
                sport = struct.unpack('H', pcap_packet_tcp['sport'])[0]
                dport = struct.unpack('H', pcap_packet_tcp['dport'])[0]
                tcp_data['srcPort'] = sport
                tcp_data['dstPort'] = dport
                tcp_data['srcIP'] = sip
                tcp_data['dstIP'] = dip

                pcap_packet_tcp['serial_num'] = string_data[l+4:l+8]
                pcap_packet_tcp['serial_num'] = pcap_packet_tcp['serial_num'][3:4] + pcap_packet_tcp['serial_num'][2:3] + pcap_packet_tcp['serial_num'][1:2] + pcap_packet_tcp['serial_num'][0:1]
                serial_num = struct.unpack('I', pcap_packet_tcp['serial_num'])[0]
                tcp_data['sequence_num'] = serial_num

                pcap_packet_tcp['ack_num'] = string_data[l+8:l+12]
                ack_num = struct.unpack('I',pcap_packet_tcp['ack_num'])[0]
                tcp_data['acknowledgment_number'] = ack_num

                pcap_packet_tcp['tcplen'] = string_data[l+12:l+13]
                tcp_len_ascii = struct.unpack('B', pcap_packet_tcp['tcplen'])[0]
                tcp_len = tcp_len_ascii/4
                tcp_data['header_length'] = tcp_len

                pcap_packet_tcp['reserved'] = string_data[l+13:l+14]
                reserved = struct.unpack('B', pcap_packet_tcp['reserved'])[0]
                tcp_data['reserved'] = reserved

                pcap_packet_tcp['window'] = string_data[l+14:l+16]
                pcap_packet_tcp['window'] = pcap_packet_tcp['window'][1:2] + pcap_packet_tcp['window'][0:1]
                window = struct.unpack('h', pcap_packet_tcp['window'])[0]
                tcp_data['window'] = window

                pcap_packet_tcp['checksum'] = string_data[l+16:l+18]
                pcap_packet_tcp['checksum'] = pcap_packet_tcp['checksum'][1:2] + pcap_packet_tcp['checksum'][0:1]
                checksum = struct.unpack('H', pcap_packet_tcp['checksum'])[0]
                tcp_data['checksum'] = checksum

                pcap_packet_tcp['urgent_pointer'] = string_data[l+18:l+20]
                pcap_packet_tcp['urgent_pointer'] = pcap_packet_tcp['urgent_pointer'][1:2] + pcap_packet_tcp['urgent_pointer'][0:1]
                urgent_pointer = struct.unpack('H', pcap_packet_tcp['urgent_pointer'])[0]
                tcp_data['urgent_pointer'] = urgent_pointer
                tcp['data'] = tcp_data
                tcp_str = json.dumps(repr(tcp))
                log_file.write(tcp_str + '\r\n')

                if sport == 80:
                    conversation_port = dport
                    add_len = total_len - tcp_len - 20
                    pcap_packet_tcp['data'] = string_data[l+tcp_len:l+tcp_len+add_len]

                    if add_len > 0:
                        http_info = http(serial_num, string_data[l+tcp_len:l+tcp_len+add_len], packet_num+1, add_len, sport, dport, conversation_port, tcp['timestamp'])
                        http_old_data.append(http_info)
                        http_num += 1

                elif dport == 80:
                    conversation_port = sport
                    add_len = total_len - tcp_len - 20
                    pcap_packet_tcp['data'] = string_data[l+tcp_len:l+tcp_len+add_len]

                    if add_len > 0:
                        http_info = http(serial_num, string_data[l+tcp_len:l+tcp_len+add_len], packet_num+1, add_len, sport, dport, conversation_port, tcp['timestamp'])
                        http_old_data.append(http_info)
                        http_num += 1

            elif ip_proto == 17:
                udp['uid'] = 10097
                udp['timestamp'] = timestamp
                udp['typeid'] = 851969
                udp['class'] = 'null'
                udp['method'] = 'null'
                udp['parameters'] = 'null'
                udp['return'] = 'null'
                udp['stackTrace'] = 'null'
                udp_num += 1

                pcap_packet_udp['sport'] = string_data[l:l+2]
                pcap_packet_udp['dport'] = string_data[l+2:l+4]
                pcap_packet_udp['sport'] = pcap_packet_udp['sport'][1:2]+pcap_packet_udp['sport'][0:1]
                pcap_packet_udp['dport'] = pcap_packet_udp['dport'][1:2]+pcap_packet_udp['dport'][0:1]
                sport = struct.unpack('H', pcap_packet_udp['sport'])[0]
                dport = struct.unpack('H', pcap_packet_udp['dport'])[0]
                udp_data['srcPort'] = sport
                udp_data['dstPort'] = dport
                udp_data['srcIP'] = sip
                udp_data['dstIP'] = dip

                pcap_packet_udp['len'] = string_data[l+4:l+6]
                pcap_packet_udp['len'] = pcap_packet_udp['len'][1:2] + pcap_packet_udp['len'][0:1]
                udp_len = struct.unpack('H', pcap_packet_udp['len'])[0]
                udp_data['len'] = udp_len

                pcap_packet_udp['checksum'] = string_data[l+6:l+8]
                udp_checksum = struct.unpack('H', pcap_packet_udp['checksum'])[0]
                udp_data['checksum'] = udp_checksum
                udp['data'] = udp_data
                udp_str = json.dumps(repr(udp))
                log_file.write(udp_str + '\r\n')

                if sport == 53 or dport == 53:
                    pcap_packet_dns['tran'] = string_data[l+8:l+10]
                    pcap_packet_dns['tran'] = pcap_packet_dns['tran'][1:2] + pcap_packet_dns['tran'][0:1]
                    tran = struct.unpack('H', pcap_packet_dns['tran'])[0]

                    pcap_packet_dns['flags'] = string_data[l+10:l+12]
                    pcap_packet_dns['flags'] = pcap_packet_dns['flags'][1:2] + pcap_packet_dns['flags'][0:1]
                    dns_flags = struct.unpack('H', pcap_packet_dns['flags'])[0]

                    pcap_packet_dns['que'] = string_data[l+12:l+14]
                    pcap_packet_dns['que'] = pcap_packet_dns['que'][1:2] + pcap_packet_dns['que'][0:1]
                    que = struct.unpack('H', pcap_packet_dns['que'])[0]

                    pcap_packet_dns['ans'] = string_data[l+14:l+16]
                    pcap_packet_dns['ans'] = pcap_packet_dns['ans'][1:2] + pcap_packet_dns['ans'][0:1]
                    ans = struct.unpack('H', pcap_packet_dns['ans'])[0]

                    pcap_packet_dns['auth'] = string_data[l+16:l+18]
                    pcap_packet_dns['auth'] = pcap_packet_dns['auth'][1:2] + pcap_packet_dns['auth'][0:1]
                    auth = struct.unpack('H',pcap_packet_dns['auth'])[0]

                    pcap_packet_dns['add'] = string_data[l+18:l+20]
                    pcap_packet_dns['add'] = pcap_packet_dns['add'][1:2] + pcap_packet_dns['add'][0:1]
                    add = struct.unpack('H', pcap_packet_dns['add'])[0]

                    #DNS报文内容，不包含上述12个字节
                    dns_data = string_data[l+20:l+udp_len]
                    #DNS报文的全部内容
                    dns_all_data = string_data[l+8:l+udp_len]
                    #分别解析源端口和目标端口为53的数据包
                    if sport == 53:
                        zeros = dns_data.find('\00')
                        domain = ''
                        if len(dns_data) < 502 and zeros >= 0:
                            dns = {}
                            dns_datas = {}
                            dns['uid'] = 10097
                            dns['typeid'] = 983041
                            dns['class'] = 'null'
                            dns['parameters'] = 'null'
                            dns['stackTrace'] = 'null'
                            dns['return'] = 'null'
                            dns['timestamp'] = 'null'
                            #domainName部分
                            dns_domain = dns_data[0:zeros]
                            #对未压缩的域名情况进行解析
                            try:
                                queries_domain = dns_data_queries(domain, dns_domain)
                                dns_datas['name'] = queries_domain[1:]
                            except Exception, ex:
                                pass
                            #解析type字段
                            dns_type = struct.unpack('H',dns_data[zeros+2:zeros+3]+dns_data[zeros+1:zeros+2])[0]
                            dns_type_string = dns_type_write(dns_type)
                            dns_datas['type'] = dns_type_string
                            #解析class字段
                            dns_class = struct.unpack('H',dns_data[zeros+4:zeros+5]+dns_data[zeros+3:zeros+4])[0]
                            dns_class_string = dns_class_write(dns_class)
                            dns_datas['class'] = dns_class_string
                            dns['data'] = dns_datas
                            dns_str = json.dumps(repr(dns))
                            log_file.write(dns_str + '\r\n')
                            #创建answers节点
                            dns = {}
                            dns_datas = {}
                            dns['uid'] = 10097
                            dns['typeid'] = 983042
                            dns['class'] = 'null'
                            dns['parameters'] = 'null'
                            dns['stackTrace'] = 'null'
                            dns['return'] = 'null'
                            dns['timestamp'] = 'null'
                            #解析answers字段
                            domain_name_list = []
                            dns_answer_data = dns_data[zeros+5:]
                            try:
                                dns_answers_write(dns, dns_datas, dns_answer_data, dns_all_data, domain_name_list)
                            except Exception, ex:
                                pass
                    elif dport == 53:
                        zeros = dns_data.find('\00')
                        domain = ''
                        if len(dns_data) < 502 and zeros >= 0:
                            dns = {}
                            dns_datas = {}
                            dns['uid'] = 10097
                            dns['typeid'] = 983041
                            dns['class'] = 'null'
                            dns['parameters'] = 'null'
                            dns['stackTrace'] = 'null'
                            dns['return'] = 'null'
                            dns['timestamp'] = 'null'
                            dns_domain = dns_data[0:zeros]
                            #对域名未压缩的情况进行解析
                            try:
                                queries_domain = dns_data_queries(domain, dns_domain)
                                dns_datas['name'] = queries_domain[1:]
                            except Exception, ex:
                                pass
                            dns_type = struct.unpack('H',dns_data[zeros+2:zeros+3]+dns_data[zeros+1:zeros+2])[0]
                            dns_type_string = dns_type_write(dns_type)
                            dns_datas['type'] = dns_type_string
                            dns_class = struct.unpack('H',dns_data[zeros+4:zeros+5]+dns_data[zeros+3:zeros+4])[0]
                            dns_class_string = dns_class_write(dns_class)
                            dns_datas['class'] = dns_class_string
                            dns['data'] = dns_datas
                            dns_str = json.dumps(repr(dns))
                            log_file.write(dns_str + '\r\n')

        #下一段数据
        i = i + packet_len + 16
        j = j + packet_len + 16
        k = k + packet_len + 16
        l = l + packet_len + 16
        packet_num += 1

    fpcap.close()

    http_old_data_parse(http_old_data)

#对未压缩的域名的处理，域名长度大于0时，表示此时有域名可解析，先读取域名长度字节，接着读取该长度的字节，最后以\00结束
def dns_data_queries(domain_name, string):
    while len(string) > 0:
        length = struct.unpack('b',string[0:1])[0]
        domain_name = domain_name + '.' +str(string[1:1+length])
        string = string[1+length:]
    return domain_name

#解析dns中的type字段
def dns_type_write(dns_type):
    if dns_type == 1:
        dns_type_string = 'A'
    elif dns_type == 2:
        dns_type_string = 'NS'
    elif dns_type == 5:
        dns_type_string = 'CNAME'
    elif dns_type == 6:
        dns_type_string = 'SOA'
    elif dns_type == 11:
        dns_type_string = 'WKS'
    elif dns_type == 12:
        dns_type_string = 'PTR'
    elif dns_type == 13:
        dns_type_string = 'HINFO'
    elif dns_type == 15:
        dns_type_string = 'MX'
    elif dns_type == 16:
        dns_type_string = 'TXT'
    elif dns_type == 17:
        dns_type_string = 'RP'
    elif dns_type == 18:
        dns_type_string = 'AFSDB'
    elif dns_type == 24:
        dns_type_string = 'SIG'
    elif dns_type == 25:
        dns_type_string = 'KEY'
    elif dns_type == 28:
        dns_type_string = 'AAA'
    elif dns_type == 29:
        dns_type_string = 'LOC'
    elif dns_type == 33:
        dns_type_string = 'SRV'
    elif dns_type == 35:
        dns_type_string = 'NAPTR'
    elif dns_type == 36:
        dns_type_string = 'KX'
    elif dns_type == 37:
        dns_type_string = 'CERT'
    elif dns_type == 39:
        dns_type_string = 'DNAME'
    elif dns_type == 41:
        dns_type_string = 'OPT'
    elif dns_type == 42:
        dns_type_string = 'APL'
    elif dns_type == 43:
        dns_type_string = 'DS'
    elif dns_type == 44:
        dns_type_string = 'SSHFP'
    elif dns_type == 45:
        dns_type_string = 'IPSECKEY'
    elif dns_type == 46:
        dns_type_string = 'RRSIG'
    elif dns_type == 47:
        dns_type_string = 'NSEC'
    elif dns_type == 48:
        dns_type_string = 'DNSKEY'
    elif dns_type == 49:
        dns_type_string = 'DHCID'
    elif dns_type == 50:
        dns_type_string = 'NSEC3'
    elif dns_type == 51:
        dns_type_string = 'NSEC3PARAM'
    elif dns_type == 52:
        dns_type_string = 'TLSA'
    elif dns_type == 55:
        dns_type_string = 'HIP'
    elif dns_type == 59:
        dns_type_string = 'CDS'
    elif dns_type == 60:
        dns_type_string = 'CDNSKEY'
    elif dns_type == 249:
        dns_type_string = 'TKEY'
    elif dns_type == 250:
        dns_type_string = 'TSIG'
    elif dns_type == 251:
        dns_type_string = 'IXFR'
    elif dns_type == 252:
        dns_type_string = 'AXFR'
    elif dns_type == 255:
        dns_type_string = 'ANY'
    elif dns_type == 257:
        dns_type_string = 'CAA'
    elif dns_type == 32768:
        dns_type_string = 'TA'
    elif dns_type == 32769:
        dns_type_string = 'DLV'
    else:
        dns_type_string = dns_type
    return dns_type_string

#解析dns中的class字段
def dns_class_write(dns_class):
    if dns_class == 1:
        dns_class_string = 'IN'
    else:
        dns_class_string = dns_class
    return dns_class_string

#解析dns中answers部分字段
def dns_answers_write(dns, dns_data, string, all_string, domain_name_list):
    global domain_name_combine
    if len(string) > 0:
        data_length = struct.unpack('H',string[11:12]+string[10:11])[0]
        answer_string = string[0:12+data_length]
        #判断answers字段第一个字节是否为'0xC0'
        answer_string0 = struct.unpack('B',answer_string[0:1])[0]
        answer_string1 = struct.unpack('B',answer_string[1:2])[0]
        if answer_string0 == 192:
            dns_domain_string = all_string[answer_string1:]
            domain_end = dns_domain_string.find('\00')
            domain_compress = dns_domain_string.find('\xc0')
            #域名未压缩的情况
            if domain_end < domain_compress:
                domain = ''
                name_string = all_string[answer_string1:answer_string1+domain_end]
                domain_name_string = dns_data_queries(domain,name_string)
                dns_data['name'] = domain_name_string[1:]
            else:
                combine_domain(answer_string1, all_string, domain_name_list)
                for each in domain_name_list:
                    domain_name_combine += each
                dns_data['name'] = domain_name_combine
                del domain_name_list[0:len(domain_name_list)]
                domain_name_combine = ''
        #解析answers中的type
        dns_type_string = dns_type_write(struct.unpack('H',answer_string[3:4]+answer_string[2:3])[0])
        dns_data['type'] = dns_type_string
        #解析answers中的class
        dns_class_string = dns_class_write(struct.unpack('H',answer_string[5:6]+answer_string[4:5])[0])
        dns_data['class'] = dns_class_string
        #解析answers中的ttl
        answer_ttl = struct.unpack('I',answer_string[9:10]+answer_string[8:9]+answer_string[7:8]+answer_string[6:7])[0]
        dns_data['ttl'] = answer_ttl
        answer_type = struct.unpack('H',answer_string[3:4]+answer_string[2:3])[0]
        #解析A，NS，CNAME
        if answer_type == 1:
            address = str(struct.unpack('B',answer_string[12:13])[0]) + '.' + str(struct.unpack('B',answer_string[13:14])[0]) + '.' + str(struct.unpack('B',answer_string[14:15])[0]) + '.' + str(struct.unpack('B',answer_string[15:16])[0])
            dns_data['address'] = address
            dns['data'] = dns_data
            dns_str = json.dumps(repr(dns))
            log_file.write(dns_str + '\r\n')
        elif answer_type == 5:
            cname_string = string[12:12+data_length]
            cname_string_end = cname_string.find('\00')
            if cname_string_end > 0:
                domain = ''
                try:
                    domain_name_string = dns_data_queries(domain,string[12:12+cname_string_end])
                    dns_data['cname'] = domain_name_string[1:]
                except Exception, ex:
                    pass
            else:
                domain = ''
                cname_string_compress = cname_string.find('\xc0')
                dns_data_queries_front(domain, string[12:12+cname_string_compress])
                cname_string_offset = struct.unpack('B',string[13+cname_string_compress:14+cname_string_compress])[0]
                combine_domain(cname_string_offset, all_string)
                for each in domain_name_list:
                    domain_name_combine += each
                dns_data['cname'] = domain_name_combine
                del domain_name_list[0:len(domain_name_list)]
                domain_name_combine = ''
            dns['data'] = dns_data
            dns_str = json.dumps(repr(dns))
            log_file.write(dns_str + '\r\n')
        elif answer_type == 2:
            ns_string = string[12:12+data_length]
            ns_string_end = ns_string.find('\00')
            if ns_string_end > 0:
                domain_name_string = dns_data_queries(string[12:12+ns_string_end])
                dns_data['name_server'] = domain_name_string[1:]
            else:
                domain = ''
                ns_string_compress = ns_string.find('\xc0')
                dns_data_queries_front(domain,string[12:12+ns_string_compress])
                ns_string_offset = struct.unpack('B', string[13+ns_string_compress:14+ns_string_compress])[0]
                combine_domain(ns_string_offset, all_string)
                for each in domain_name_list:
                    domain_name_combine += each
                dns_data['name_server'] = domain_name_combine
                del domain_name_list[0:len(domain_name_list)]
                domain_name_combine = ''
            dns['data'] = dns_data
            dns_str = json.dumps(repr(dns))
            log_file.write(dns_str + '\r\n')
        else:
            print 'There are other kinds of dns_answer packets...'

#解析域名压缩部分，遇到\c0就读取偏移量，并找到相应的位置进行解析，多次压缩的情况进行递归解压
def combine_domain(offset, all_string, domain_name_list):
    domain = ''
    part_string = all_string[offset:]
    part_string_end = part_string.find('\00')
    part_string_compress = part_string.find('\xc0')
    if part_string_end < part_string_compress:
        dns_data_queries_behind(domain, all_string[offset:offset+part_string_end], domain_name_list)
    else:
        dns_data_queries_front(domain, all_string[offset:offset+part_string_compress], domain_name_list)
        offset = struct.unpack('B',part_string[part_string_compress+1:part_string_compress+2])[0]
        combine_domain(offset, all_string, domain_name_list)

#部分压缩域名情况处理，对未压缩部分数据取出来解析，压缩过的按照偏移量找到具体位置
def dns_data_queries_front(domain_name, string, domain_name_list):
    if len(string) > 0:
        length = struct.unpack('b',string[0:1])[0]
        domain_name = domain_name + '.' +str(string[1:1+length])
        string = string[1+length:]
        if len(string) > 0:
            dns_data_queries_front(domain_name, string, domain_name_list)
        else:
            domain_name_list.append(domain_name[1:] + '.')

def dns_data_queries_behind(domain_name, string, domain_name_list):
    if len(string) > 0:
        length = struct.unpack('b',string[0:1])[0]
        if length != 0:
            domain_name = domain_name + '.' +str(string[1:1+length])
        string = string[1+length:]
        dns_data_queries_behind(domain_name, string, domain_name_list)
    elif len(string) == 0:
        domain_name_behind = domain_name[1:]
        domain_name_list.append(domain_name_behind)

#对存放在http_old_data列表中的http数据包进行处理
def http_old_data_parse(http_old_data):
    sort_by_num(http_old_data, 'conversation_port')
    print_data_packet(http_old_data)
    #最后一段会话运行函数对会话进行处理
    sort_by_num(request_datalist,'serialnum')
    printhttp_finaldata(request_datalist)
    request_txt.write('='*5)
    sort_by_num(response_datalist,'serialnum')
    printhttp_finaldata(response_datalist)
    response_txt.write('='*5)

    #文件写入结束
    request_txt.close()
    response_txt.close()

#对列表中的数据按照某一关键值排序
def sort_by_num(lst,attr):
    lst.sort(key=operator.attrgetter(attr))

def print_data_packet(lst):
    for per in lst:
        per.classify_data_packet()

def printhttp_finaldata(lst):
    for per in lst:
        per.print_http_data()
    if len(data_assist) > 0:
        flag = max(data_assist)[0:4]
        #每个会话中的最后序列号的数据包
        if flag == 'GET ' or flag == 'POST':
            request_txt.write(max(data_assist))
            del(data_assist[0:len(data_assist)])
        elif max(data_assist) == '\00':
            del(data_assist[0:len(data_assist)])
        elif max(data_assist) != '\r\n':
            response_txt.write(max(data_assist))
            del(data_assist[0:len(data_assist)])
        del(request_serial_assist[0:len(request_serial_assist)])
        del(response_serial_assist[0:len(response_serial_assist)])

#取会话
def get_data_request(string):
    get_offset = string.find('GET')
    post_offset = string.find('POST')
    if get_offset > 0 and post_offset > 0:
        offset_start = min(get_offset, post_offset)
    elif get_offset > 0 and post_offset < 0:
        offset_start = get_offset
    elif get_offset < 0 and post_offset > 0:
        offset_start = post_offset
    else:
        offset_start = 0
    offset_end = string[offset_start:].find('=====')
    return_str = string[offset_start:(offset_start+offset_end)]
    if len(return_str) > 0:
        return return_str
    else:
        pass

def get_data_response(string):
    offset_start = string.find('HTTP')
    offset_end = string[offset_start:].find('=====')
    return string[offset_start:(offset_start+offset_end)]


#将上述得到的request和response文件进行划分
def http_file_divide(pcapfile):

    #读取处理请求和相应的报文数据
    finaldata_request = open(request_txt_string,'rb')
    string_request = finaldata_request.read()
    request = string_request

    finaldata_response = open(response_txt_string,'rb')
    string_response = finaldata_response.read()
    response = string_response
    #i标记每个会话的顺序，一个会话写入一个result.txt文本文件中
    i = 1

    while len(request) > 5 and len(response) > 5:
        conversation_filename = all_path + 'result' + str(i) + '.txt'
        conversation_data = open(conversation_filename,'wb')
        #以=====分割不同的会话
        request_conversation_data = str(get_data_request(request))
        response_conversation_data = str(get_data_response(response))
        request_conversation_offset = request.find(request_conversation_data[0:20]) + len(request_conversation_data)
        response_conversation_offset = response.find(response_conversation_data[0:20]) + len(response_conversation_data)

        #对每个会话的结束进行判断
        while len(request_conversation_data) > 0 and len(response_conversation_data) > 0:
            #request处理
            #request以空行分割
            request_enter_offset = request_conversation_data.find('\r\n\r\n')
            if request_enter_offset > 0:
                request_contentlength = request_conversation_data[0:request_enter_offset].find('Content-Length: ')
                if request_contentlength > 0:
                    request_contentlength_enter = request_conversation_data[request_contentlength:].find('\r\n')
                    request_content_length = request_conversation_data[request_contentlength+16:request_contentlength+request_contentlength_enter]
                    request_data = request_conversation_data[0:request_enter_offset+4+int(request_content_length)]
                    if len(request_data) < request_enter_offset+4+int(request_content_length):
                        conversation_data.write(request_conversation_data[0:request_enter_offset+4])
                        request_conversation_data = request_conversation_data[request_enter_offset+4:]
                    elif request_conversation_data[request_enter_offset+4:request_enter_offset+8] == 'POST':
                        conversation_data.write(request_conversation_data[0:request_enter_offset+4])
                        request_conversation_data = request_conversation_data[request_enter_offset+4:]
                    else:
                        conversation_data.write(request_data)
                        request_conversation_data = request_conversation_data[request_enter_offset+4+int(request_contentlength):]
                else:
                    request_data = request_conversation_data[0:request_enter_offset]
                    conversation_data.write(request_data)
                    #写入一空行
                    conversation_data.write('\r\n\r\n')
                    request_conversation_data = request_conversation_data[request_enter_offset+4:]
            else:
                break
            #response处理
            response_date = response_conversation_data.find('Date: ')
            #换行部分的偏移量
            blank_flag = response_conversation_data[response_date:].find('\r\n\r\n')
            #Content-Length: 的偏移量
            response_contentlength = response_conversation_data[0:response_date+blank_flag].find('Content-Length: ')
            response_transferencoding = response_conversation_data[0:response_date+blank_flag].find('Transfer-Encoding: chunked')
            #对是否含有Content-Length进行不同的处理
            if response_contentlength > 0:
                #回车的偏移量，从Content-length开始算起
                content_length_enter = response_conversation_data[response_contentlength:].find('\r\n')
                #Content-Lenght的字符串部分
                content_length = response_conversation_data[response_contentlength+16:response_contentlength+content_length_enter]
                response_data = response_conversation_data[0:response_date+blank_flag+4+int(content_length)]
                conversation_data.write(response_data)
                response_conversation_data = response_conversation_data[response_date+blank_flag+4+int(content_length):]
            elif response_transferencoding>0:
                #chunk编码不知道数据部分多少字节，因此找两空行之间的部分为数据部分
                another_blank = response_conversation_data[response_date+blank_flag+4:].find('\r\n\r\n')
                response_data = response_conversation_data[0:response_date+blank_flag+another_blank+8]
                conversation_data.write(response_data)
                response_conversation_data = response_conversation_data[response_date+blank_flag+another_blank+8:]
            else:
                #其他情况只读取报文部分
                response_data = response_conversation_data[0:response_date+blank_flag+4]
                conversation_data.write(response_data)
                response_conversation_data = response_conversation_data[response_date+blank_flag+4:]
        # 下一会话之后的数据部分
        request = request[request_conversation_offset+6:]
        response = response[response_conversation_offset+6:]
        #关闭某会话存储文件
        conversation_data.close()
        create_http_xml(conversation_filename, content_path)
        i += 1
        #将结果文件移动至result目录下
        shutil.copy(conversation_filename,file_path)
        os.remove(conversation_filename)

    shutil.copy(request_txt_string,file_path)
    shutil.copy(response_txt_string,file_path)
    os.remove(request_txt_string)
    os.remove(response_txt_string)
    #文件写入结束
    finaldata_request.close()
    finaldata_response.close()

#对每个会话中的数据进行处理生成xml文件
def create_http_xml(filename, content_path):
    http_file = open(filename,'rb')
    http_data_string = http_file.read()
    print_xml_file(http_data_string, content_path)
    http_file.close()

#分割request和response的文件并生成对应信息，存储在xml文件中
def print_xml_file(string, content_path):
    global content_filename
    if len(string) > 0:
        http = {}
        http_data = {}
        http['uid'] = 10097
        http['typeid'] = 917505
        http['class'] = 'null'
        http['parameters'] = 'null'
        http['return'] = 'null'
        http['stackTrace'] = 'null'
        #对request部分进行处理
        #得到Method的值
        head_offset = string.find('\r\n\r\n')
        head = string[0:head_offset]
        method_offset = head.find(' ')
        method = head[0:method_offset]
        http_data['method'] = method
        #得到Method后的部分路径值
        path_behind_offset = head[method_offset+1:].find(' ')
        path_behind = head[method_offset+1:method_offset+1+path_behind_offset]
        #得到Host的值
        host_offset = head.find('Host:')
        if host_offset < 0:
            host_offset = head.find('host: ')
        host_enter_offset = head[host_offset+6:].find('\r\n')
        if host_enter_offset > 0:
            host = head[host_offset+6:host_offset+6+host_enter_offset]
        else:
            host = head[host_offset+6:]
        http_data['host'] = host
        #得到Path的值
        path = host + path_behind
        http_data['path'] = path
        http_data['port'] = 80
        http_data['query'] = 'null'
        http_data['scheme'] = 'null'
        #得到Content-Type的值
        head_content_type_offset = head.find('Content-Type: ')
        if head_content_type_offset > 0:
            head_content_type_offset_enter = head[head_content_type_offset:].find('\r\n')
            if head_content_type_offset_enter > 0:
                head_content_type = head[head_content_type_offset:head_content_type_offset+head_content_type_offset_enter]
            else:
                head_content_type_flag = re.compile('Content-Type: (.*)')
                head_content_type = head_content_type_flag.findall(head)[0]
        # print host,path
        #如果方法是Post的讨论
        if method == 'POST':
            #得到Content-Length的值
            head_content_offset = head.find('Content-Length: ')
            if head_content_offset > 0:
                head_content_enter_offset = head[head_content_offset+16:].find('\r\n')
                if head_content_enter_offset > 0:
                    head_content_length = head[head_content_offset+16:head_content_offset+16+head_content_enter_offset]
                else:
                    head_content_flag = re.compile('Content-Length: (.\d*)')
                    head_content_length = head_content_flag.findall(head)[0]
                    head_content_length = int(head_content_length)
            else:
                head_content_offset = head.find('Content-length: ')
                if head_content_offset > 0:
                    head_content_enter_offset = head[head_content_offset+16:].find('\r\n')
                    if head_content_enter_offset > 0:
                        head_content_length = head[head_content_offset+16:head_content_offset+16+head_content_enter_offset]
                    else:
                        head_content_flag = re.compile('Content-length: (.\d*)')
                        head_content_length = head_content_flag.findall(head)[0]
                        head_content_length = int(head_content_length)
            head_content = string[head_offset+4:head_offset+4+int(head_content_length)]
            if head_content[0:4] != 'POST':
                content_file = write_file(head_content, content_path)
                head_content_path = content_path + content_file
                http_data['content'] = head_content_path
                boundary_offset = head.find('boundary=')
                filename_offset = head_content.find('filename')
                if boundary_offset > 0 and filename_offset > 0:
                    filename_flag = re.compile('filename="(.*)"')
                    filename = filename_flag.findall(head_content)[0]
                    if len(filename) > 0:
                        http_data['file_name'] = filename
                        http_data['file_type'] = filename.split('.')[-1]
                        if filename.split('.')[-1] == 'apk' or filename.split('.')[-1] == 'elf':
                            http_data['isAPK_orELF'] = 'true'
                http['data'] = http_data
                http_request_str = json.dumps(repr(http))
                log_file.write(http_request_str + '\r\n')
                #处理response部分
                http = {}
                http_data = {}
                http['uid'] = 10097
                http['typeid'] = 917506
                http['class'] = 'null'
                http['timestamp'] = 'null'
                http['parameters'] = 'null'
                http['return'] = 'null'
                http['stackTrace'] = 'null'
                response_head_offset = string[head_offset+4+int(head_content_length):].find('\r\n\r\n')
                response_head = string[head_offset+4+int(head_content_length):head_offset+4+int(head_content_length)+response_head_offset]
                #得到status_line的值
                status_enter_offset = response_head.find('\r\n')
                status_line = response_head[0:status_enter_offset]
                if len(status_line) > 0:
                    http_offset = status_line.find('HTTP')
                    if http_offset >= 0:
                        status_line = status_line[http_offset:]
                        http_data['status_line'] = status_line
                content_type_offset = response_head.find('Content-Type: ')
                if content_type_offset > 0:
                    content_type_offset_enter = response_head[content_type_offset:].find('\r\n')
                    if content_type_offset_enter > 0:
                        content_type = response_head[content_type_offset:content_type_offset+content_type_offset_enter]
                    else:
                        content_type_flag = re.compile('Content-Type: (.*)')
                        content_type = content_type_flag.findall(response_head)[0]
                Content_Length_offset = response_head.find('Content-Length: ')
                Transfer_Encoding_offset = response_head.find('Transfer-Encoding: chunked')
                if Content_Length_offset > 0:
                    content_length_enter = response_head[Content_Length_offset+16:].find('\r\n')
                    if content_length_enter > 0:
                        response_content_length = response_head[Content_Length_offset+16:Content_Length_offset+16+content_length_enter]
                    else:
                        response_content_length_flag = re.compile('Content-Length: (.\d*)')
                        response_content_length = response_content_length_flag.findall(response_head)[0]
                        response_content_length = int(response_content_length)
                    content = string[head_offset+4+int(head_content_length)+response_head_offset+4:head_offset+4+int(head_content_length)+response_head_offset+4+int(response_content_length)]
                    request_length_content_file = write_file(content, content_path)
                    request_length_content_path = content_path + request_length_content_file
                    http_data['content'] = request_length_content_path
                    http['data'] = http_data
                    http_str = json.dumps(repr(http))
                    log_file.write(http_str + '\r\n')
                    string = string[head_offset+4+int(head_content_length)+response_head_offset+4+int(response_content_length):]
                    print_xml_file(string, content_path)
                elif Transfer_Encoding_offset > 0:
                    content_chunked_offset = string[head_offset+4+int(head_content_length)+response_head_offset+4:].find('\r\n\r\n')
                    content_chunked = string[head_offset+4+int(head_content_length)+response_head_offset+4:head_offset+4+int(head_content_length)+response_head_offset+4+content_chunked_offset]
                    request_chunck_content_file = write_file(content_chunked, content_path)
                    request_chunck_content_path = content_path + request_chunck_content_file
                    http_data['content'] = request_chunck_content_path
                    http['data'] = http_data
                    http_str = json.dumps(repr(http))
                    log_file.write(http_str + '\r\n')
                    string = string[head_offset+4+int(head_content_length)+response_head_offset+4+content_chunked_offset+4:]
                    print_xml_file(string, content_path)
            else:
                boundary_offset = head.find('boundary=')
                filename_offset = head_content.find('filename')
                if boundary_offset > 0 and filename_offset > 0:
                    filename_flag = re.compile('filename="(.*)"')
                    filename = filename_flag.findall(head_content)[0]
                    if len(filename) > 0:
                        http_data['file_name'] = filename
                        http_data['file_type'] = filename.split('.')[-1]
                        if filename.split('.')[-1] == 'apk' or filename.splt('.')[-1] == 'elf':
                            http_data['isAPK_orELF'] = 'true'
                        http['data'] = http_data
                        http_str = json.dumps(repr(http))
                        log_file.write(http_str + '\r\n')
                else:
                    http['data'] = http_data
                    http_str = json.dumps(repr(http))
                    log_file.write(http_str + '\r\n')
        else:
            http['data'] = http_data
            http_request_str = json.dumps(repr(http))
            log_file.write(http_request_str + '\r\n')
            http = {}
            http_data = {}
            http['uid'] = 10097
            http['typeid'] = 917506
            http['class'] = 'null'
            http['timestamp'] = 'null'
            http['parameters'] = 'null'
            http['return'] = 'null'
            http['stackTrace'] = 'null'
            response_head_offset = string[head_offset+4:].find('\r\n\r\n')
            response_head = string[head_offset+4:head_offset+4+response_head_offset]
            #得到status_line的值
            status_enter_offset = response_head.find('\r\n')
            status_line = response_head[0:status_enter_offset]
            if len(status_line) > 0:
                http_offset = status_line.find('HTTP')
                if http_offset >= 0:
                    status_line = status_line[http_offset:]
                    http_data['status_line'] = status_line
            response_content_type_offset = response_head.find('Content-Type: ')
            if response_content_type_offset > 0:
                response_content_type_offset_enter = response_head[response_content_type_offset:].find('\r\n')
                if response_content_type_offset_enter > 0:
                    response_content_type = response_head[response_content_type_offset:response_content_type_offset+response_content_type_offset_enter]
                else:
                    response_content_type_flag = re.compile('Content-Type: (.\d*)')
                    response_content_type = response_content_type_flag.findall(response_head)[0]
            Content_Length_offset = response_head.find('Content-Length: ')
            Transfer_Encoding_offset = response_head.find('Transfer-Encoding: chunked')
            if Content_Length_offset > 0:
                content_length_enter = response_head[Content_Length_offset+16:].find('\r\n')
                if content_length_enter > 0:
                    response_content_length = response_head[Content_Length_offset+16:Content_Length_offset+16+content_length_enter]
                else:
                    content_length_flag = re.compile('Content-Length: (.\d*)')
                    response_content_length = content_length_flag.findall(response_head)[0]
                    response_content_length = int(response_content_length)
                content = string[head_offset+4+response_head_offset+4:head_offset+4+response_head_offset+4+int(response_content_length)]
                response_length_content_file = write_file(content, content_path)
                response_length_content_path = content_path + response_length_content_file
                http_data['content'] = response_length_content_path
                http['data'] = http_data
                http_str = json.dumps(repr(http))
                log_file.write(http_str + '\r\n')
                string = string[head_offset+4+response_head_offset+4+int(response_content_length):]
                print_xml_file(string, content_path)
            elif Transfer_Encoding_offset > 0:
                content_chunked_offset = string[head_offset+4+response_head_offset+4:].find('\r\n\r\n')
                content_chunked = string[head_offset+4+response_head_offset+4:head_offset+4+response_head_offset+4+content_chunked_offset]
                response_chunck_content_file = write_file(content_chunked, content_path)
                response_chunck_content_path = content_path + response_chunck_content_file
                http_data['content'] = response_chunck_content_path
                http['data'] = http_data
                http_str = json.dumps(repr(http))
                log_file.write(http_str + '\r\n')
                string = string[head_offset+4+response_head_offset+4+content_chunked_offset+4:]
                print_xml_file(string, content_path)

def write_file(string, content_path):
    m = hashlib.md5()
    m.update(string)
    file_name = m.hexdigest()
    content_filename = file_name
    f = open(content_filename, 'wb')
    f.write(string)
    f.close()
    shutil.copy(content_filename, content_path)
    os.remove(content_filename)
    return file_name

def main():
    pcap_parse(pcapfile)
    http_file_divide(pcapfile)
    print 'mission complete!'

if __name__ == '__main__':
    main()
    log_file.close()
