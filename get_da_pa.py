#!/usr/bin/python

import requests
from concurrent.futures import ThreadPoolExecutor as Pool
from lxml import etree


def get_links(token):
    links = []
	url = 'https://seo-rank.my-addr.com/api2/moz+alexa+sr+maj+spam/{}/{}'
    with open('ssss.html', 'r') as f:
        html = f.read()
        dom = etree.HTML(bytes(html, encoding='utf-8'))
        k_lists = dom.xpath('/html/body/table/tbody/tr')        
        for i, ele in enumerate(k_lists, 1):
            link = ele.xpath('../tr[' + str(i) + ']/td[2]/div/div')[0].text.replace('\n', '').strip()
            links.append(url.format(token, link))
    return links


def task(url):
    return requests.get(url, timeout=30)


if __name__ == '__main__':
    TOKEN = 'yourtoken'
    links = get_links(TOKEN)
    pool = Pool(max_workers=5)  # 线程池每次装5个线程  其他等待执行完在进入线程池
    results = pool.map(task, links)
    for ret in results:
        if ret.status_code == 200:
            print('该网站{}的DA/PA为:{}/{}'.format(ret.url, ret.json().get('da'), ret.json().get('pa')))
