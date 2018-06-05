#!/usr/bin/env python
# -*- coding: utf8 -*-

import sys
import redis
import random
import json
import time
from threading import Thread
from datetime import datetime

try:
    alarm_log_period_count = sys.argv[0]
    ex_log_period_count = sys.argv[1]
except Exception as ex:
    alarm_log_period_count = 10
    ex_log_period_count = 10

EX_LOG_TYPE = (
    (0, '业务资产主动外连日志'),
    (1, 'DGA域名发现日志'),
    (2, 'HTTP代理发现日志'),
    (3, 'SOCKS代理发现日志'),
    (4, 'DNS发现日志'),
    (5, 'DNS Tunnel发现日志'),
    (6, 'reGeorg Tunnel发现日志'),
    (7, '异地账号登录日志'),
    (8, '暴力破解日志'),
    (9, '明文密码泄漏日志'),
    (10, '弱口令监测日志'),
    (11, '敏感关键词邮件日志'),
    (12, '敏感后缀邮件日志'),
    (13, '邮件攻击日志'),
    (14, '邮件类恶意软件日志'),
    (15, '非邮件类恶意软件日志'),
)

THREAT_LEVEL = (
    (0, "低危"),
    (1, "中危"),
    (2, "高危"),
    (3, "危急"),
)
ALARM_LOG_TYPE = (
    ('10010000', "APT事件"),
    ('10020000', "用户自定义"),
    ('10030000', "其他APT事件"),
    ('11010000', "应用程序查询"),
    ('11020000', "数据库侦查"),
    ('11030000', "DNS侦察"),
    ('11040000', "FTP侦察"),
    ('11050000', "端口扫描"),
    ('11060000', "主机查询"),
    ('11070000', "邮件侦察"),
    ('11080000', "网络扫描"),
    ('11090000', "SNMP侦察"),
    ('110A0000', "SSH侦察"),
    ('110B0000', "Telnet侦察"),
    ('110D0000', "其他侦察"),
    ('14010000', "后门程序"),
    ('14020000', "僵尸网络"),
    ('14030000', "低速传递程序"),
    ('14040000', "特洛伊木马"),
    ('14050000', "电脑病毒"),
    ('14060000', "间谍软件"),
    ('14070000', "恶意广告"),
    ('14080000', "远控木马"),
    ('14090000', "键盘记录"),
    ('140A0000', "窃密木马"),
    ('140B0000', "网络蠕虫"),
    ('140C0000', "勒索软件"),
    ('140D0000', "黑市工具"),
    ('140E0000', "流氓推广"),
    ('14110000', "其他恶意软件"),
    ('15010000', "数据库拒绝服务"),
    ('15020000', "web拒绝服务"),
    ('15040000', "其他拒绝服务"),
    ('16010000', "SQL注入"),
    ('16020000', "URL跳转"),
    ('16030000', "代码执行"),
    ('16040000', "非授权访问/权限绕过"),
    ('16050000', "跨站脚本攻击(XSS)"),
    ('16060000', "跨站请求伪造(CSRF)"),
    ('16070000', "逻辑/设计错误"),
    ('16080000', "敏感信息/重要文件泄露"),
    ('16090000', "命令执行"),
    ('160A0000', "默认配置不当"),
    ('160B0000', "目录遍历"),
    ('160C0000', "配置不当/错误"),
    ('160D0000', "权限许可和访问控制"),
    ('160E0000', "弱口令"),
    ('160F0000', "文件包含"),
    ('16100000', "文件读取"),
    ('16110000', "文件上传"),
    ('16120000', "文件下载"),
    ('16130000', "文件写入"),
    ('16140000', "系统/服务配置不当"),
    ('16150000', "溢出攻击"),
    ('16160000', "信息泄露"),
    ('16170000', "浏览器劫持"),
    ('16180000', "暴力猜解"),
    ('16190000', "网络钓鱼"),
    ('161A0000', "恶意样本执行"),
    ('161B0000', "恶意样本投递"),
    ('161C0000', "webshell上传"),
    ('161F0000', "其他攻击利用"),
)

ATTACK_CHAIN_TAG = (
    ("0x01000000", "侦察"),
    ("0x02000000", "入侵"),
    ("0x03000000", "命令控制"),
    ("0x04000000", "横向渗透"),
    ("0x05000000", "数据外泄"),
    ("0x06000000", "痕迹清理"),
)


class Create:

    def __init__(self):
        self.redis_host = "127.0.0.1"
        self.redis_port = "3680"
        self.sys_name = "未知威胁监测系统"
        self.alarm_log_key = "alarm:log"
        self.ex_log_key = "exception:log"
        self.conn_redis = self.redis_conn()
        self.ex_log_type = [t[0] for t in EX_LOG_TYPE]  # 异常场景日志类型

    def redis_conn(self):
        pool = redis.ConnectionPool(host=self.redis_host, port=self.redis_port)
        r = redis.Redis(connection_pool=pool)
        return r

    def run(self):
        thread_list = list()
        thread_list.append(Thread(target=self.create_alarm_log_data))
        thread_list.append(Thread(target=self.create_ex_log_data))
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join()

    def create_alarm_log_data(self, alarm_log_data_list=None):
        ''' 造告警日志数据 '''

        def get_type(seq, code):
            for obj in seq:
                if obj[0] == code:
                    return obj[1]

        victim_ip = "103.240.245.44"
        attack_organization = "Generic Trojan"
        attack_ip = "52.86.22.136"
        file_md5 = "294ca5c3b55ad35c1f397b05c2b401f3"
        file_name = "wbkrfq.wbk"
        domain = "numeronez.com"
        domain_md5 = "10679e080df8632a052359e517fba5dc"
        ioc = "numeronez.com"
        remove_duplicates_str = "c90e698f35b0338a2080cb81836346a1"

        certainty_level = ["低", "中", "高"]

        alarm_type_list = [t[0] for t in alarm_log_type]
        data_format = "{}|*17|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}|*{}"

        if not alarm_log_data_list:
            alarm_log_data_list = []  # 初始化告警日志数据
        while True:
            for i in range(alarm_log_period_count):
                alarm_type_code = random.choice(alarm_type_list)
                alarm_type = get_type(alarm_type_list, alarm_type_code)
                alarm_log_data_list.append(data_format.format(
                    self.sys_name,
                    _format_time(),
                    victim_ip,  # 受害ip
                    attack_organization,  # 攻击组织
                    attack_ip,  # 攻击ip
                    alarm_type_code,  # 告警类型编码
                    alarm_type,  # 告警类型
                    file_md5,  # 文件md5
                    file_name,  # 文件名
                    str(random.choice([t[0] for t in THREAT_LEVEL])),  # 威胁级别
                    random.choice(certainty_level),  # 确信度
                    domain,  # 域名
                    domain_md5,  # 域名md5
                    ioc,
                    remove_duplicates_str,  # 去重字符串
                    random.choice(["可疑", "失陷"]),  # 攻陷状态
                    random.choice([a[0] for a in ATTACK_CHAIN_TAG]),  # 供给链标签
                    random.choice(["0", "1"])  # 是否为web攻击
                ))
            if self.conn_redis.get(self.alarm_log_key):
                self.conn_redis.delete(self.alarm_log_key)
            self.conn_redis.set(self.alarm_log_key, json.dumps(alarm_log_data_list))
            time.sleep(30)

    def create_ex_log_data(self, ex_log_data_list=None):
        ''' 造异常告警数据 '''
        if not ex_log_data_list:
            ex_log_data_list = []
        ex_log_type = [e[0] for e in EX_LOG_TYPE]
        while True:
            for i in range(ex_log_period_count):
                format_type = self.format_log_by_ex_type(random.choice(ex_log_type))
                ex_log_data_list.append(format_type.format(self._format_time()))
            if self.conn_redis.get(self.ex_log_key):
                self.conn_redis.delete(self.ex_log_key)
            self.conn_redis.set(self.ex_log_key, json.dumps(ex_log_data_list))
            time.sleep(30)

    def format_log_by_ex_type(self, ex_type):
        format_log = ""
        if ex_type == 0:
            format_log = \
                "未知威胁监测系统|*1|*198.15.21.1|*CN|*CNCGROUP China169 Backbone|*466|*172.15.14.14|*152456|*6548562|*{}"
        elif ex_type == 1:
            format_log = "未知威胁监测系统|*2|*172.15.14.13|*172.15.14.14|*172.15.14.15|*89.99%|*{}"
        elif ex_type == 2:
            format_log = "未知威胁监测系统|*3|*172.15.14.14|*172.15.14.15|*1888|*00:0c:29:4f:d5:84|*dnsserver|*http|*{}"
        elif ex_type == 3:
            format_log = "未知威胁监测系统|*4|*172.15.14.14|*172.15.14.15|*1883|*00:0c:29:4f:d5:84|*dnsserver|*socks5|*{}"
        elif ex_type == 4:
            format_log = \
                "未知威胁监测系统|*5|*172.15.14.13|*00:0c:29:4f:d5:84|* dnsserver|*172.15.14.14|*driver.updatestar.com|*1828|*1973|*66.164.108.38|* updatestar.com|*{}"
        elif ex_type == 5:
            format_log = "未知威胁监测系统|*6|*172.15.14.14|*198.15.21.2|*{}|*driver.updatestar.com"
        elif ex_type == 6:
            format_log = "未知威胁监测系统|*7|*172.15.14.14|*172.15.14.15|*driver.updatestar.com|*proxychains4 -f|*{}"
        elif ex_type == 7:
            format_log = "未知威胁监测系统|*8|*172.15.14.14|*CN|*fenggeng|*172.15.14.13|*SMTP|*20|*3|*{}"
        elif ex_type == 8:
            format_log = "未知威胁监测系统|*9|*wuyanming|*wuyan123457|*{}|*FAILED"
        elif ex_type == 9:
            format_log = "未知威胁监测系统|*10|*172.15.14.13|*SMTP|*wuyanming@360.net|*wuyan123456|*{}"
        elif ex_type == 10:
            format_log = "未知威胁监测系统|*11|*admin|*172.15.14.13|*SMTP|*123456|*{}"
        elif ex_type == 11:
            format_log = "未知威胁监测系统|*12|*172.15.14.14|*hute@360.net|*jiaxiaozhi168@sina.com,liuziyang@rxblend.com|*登录|*vpn 账号过期了|*XXX 进行反馈版权所有 XXX|*wuyanming@360.net,renbotao@360.net|*wuyanming1@360.net,renbotao1@360.net|*pastedImage.png,pastedImage|*1|*{}"
        elif ex_type == 12:
            format_log = "未知威胁监测系统|*13|*172.15.14.14|*hute@360.net|*jiaxiaozhi168@sina.com,liuziyang@rxblend.com|*vpn 账号过期了|*XXX 进行反馈版权所有 XXX|*wuyanming@360.net,renbotao@360.net|*wuyanming1@360.net,renbotao1@360.net|*pastedImage.png,pastedImage|*png,jar,exe|*{}"
        elif ex_type == 13:
            format_log = "未知威胁监测系统|*14|*hute@360.net|*jiaxiaozhi168@sina.com,liuziyang@rxblend.com|*http|*vpn 账号过期了|*{}|*233|*pdf|*sfgfgsfsfg|*3|*中|*侦察|*http://map.baidu.com/?newmap=1|*wuyanming@360.net,renbotao@360.net|*XXX 进行反馈版权所有 XXX"
        elif ex_type == 14:
            format_log = "未知威胁监测系统|*15|*http://xxxx|*XXXX|*doc|*dafsgsgdsfgdfg|*smtp|*3|*高|*侦察|*vpn 账号过期了|*{}|*hute@360.net|*jiaxiaozhi168@sina.com,liuziyang@rxblend.com|*y@126.com|*123|*pdf|*http://xxxx|*adfafsdfafasd"
        elif ex_type == 15:
            format_log = "未知威胁监测系统|*16|*http://xxxx|*XXXX|*txt|*fsdfggsssg|*http|*3|*高|*侦察|*172.15.14.14|*http://www.baidu.com|*1234|*test|*pdf|*1|*http://xxxx|*{}"
        return format_log

    def _format_time(self):
        '''
        时间格式标准化
        exp:
        输入时间为 2017-1-8 12:54:30
        返回时间为 2017-01-08 12:50:00
        '''
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        time_format = now.split(' ')
        time_hms = time_format[1].split(':')
        _hour = time_hms[0]
        _second = '00'
        ftime = "{} {}:{}:{}"
        if int(time_hms[1]) and int(time_hms[1]) % 5 == 0:
            return ftime.format(time_format[0], _hour, time_hms[1], _second)
        _minute = str(int(math.floor(int(time_hms[1]) / 5)) * 5)
        if _minute == '0':
            _minute = '00'
        return ftime.format(time_format[0], _hour, _minute, _second)


if __name__ == '__main__':
    if not alarm_log_period_count:
        print "告警日志周期数据不能为0"
        sys.exit()
    if not ex_log_period_count:
        print "异常场景日志周期数据不能为0"
        sys.exit()
    create = Create()
    create.run()
