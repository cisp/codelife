#!/usr/bin/python
from splinter.browser import Browser
from time import sleep


class Ticket(object):
    ticket_url = "https://kyfw.12306.cn/otn/leftTicket/init"
    login_url = "https://kyfw.12306.cn/otn/login/init"
    initmy_url = "https://kyfw.12306.cn/otn/index/initMy12306"
    buy = "https://kyfw.12306.cn/otn/confirmPassenger/initDc"
    username = 'username'
    pwd = 'password'
    # 选择的买票人
    name = ['name']
    fromStation = '%u6B66%u6C49%2CWHN'
    toStatioin = '%u5E94%u57CE%2CYHN'
    timeStation = '2018-02-12'
    # 车次 为0 就循环从第一个开始选票  不为0,就选择固定的车次
    order = 0
    

    def __init__(self):
        pass

    def login(self):
        self.driver.visit(self.login_url)
        self.driver.fill('loginUserDTO.user_name', self.username)
        self.driver.fill('userDTO.password', self.pwd)
        while True:
            if self.driver.url != self.initmy_url:
                sleep(1)
            else:
                break

    def start(self):
        self.driver = Browser('chrome')
        self.driver.driver.maximize_window()
        self.login()
        self.driver.visit(self.ticket_url)
        self.driver.cookies.add({"_jc_save_fromStation": self.fromStation})
        self.driver.cookies.add({"_jc_save_toStation": self.toStatioin})
        self.driver.cookies.add({"_jc_save_fromDate": self.timeStation})

        self.driver.reload()

        count = 0
        if self.order != 0:
            while self.driver.url == self.ticket_url:
                self.driver.click_link_by_id('query_ticket')
                count += 1
                try:
                    self.driver.find_by_text("预订")[self.order - 1].click()
                except Exception as ex:
                    continue
        else:
            while self.driver.url == self.ticket_url:
                self.driver.find_by_text("查询").click()
                count += 1
                try:
                    for i in self.driver.find_by_text("预订"):
                        i.click()
                        sleep(0.8)
                except Exception as ex:
                    continue

        self.driver.find_by_text(self.name).last.click()
        self.driver.click_link_by_id('submitOrder_id')
        sleep(10)


if __name__ == '__main__':
    ticket = Ticket()
    ticket.start()

