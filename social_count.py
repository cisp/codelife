#!/usr/bin/python

import json
import requests
from concurrent.futures import ThreadPoolExecutor as Pool


def get_social_data(urls):
    def task(url):
        fb_api_url = 'http://graph.facebook.com/?id={}'.format(url)
        ps_api_url = 'http://api.pinterest.com/v1/urls/count.json?url={}'.format(url)
        lki_api_url = 'http://www.linkedin.com/countserv/count/share?url={}&format=json'.format(url)
        stb_api_url = 'http://www.stumbleupon.com/services/1.01/badge.getinfo?url={}'.format(url)
        fb_s = ps_s = lki_s = stb_s = {}
        fb_r = requests.get(fb_api_url)
        if fb_r.status_code == 200:
            fb_j = fb_r.json()
            fb_s = {
                'uri': url,
                'fbc': fb_j.get('share').get('comment_count'),
                'fbs': fb_j.get('share').get('share_count'),
            }
        ps_r = requests.get(ps_api_url)
        if ps_r.status_code == 200:
            ps_j = ps_r.json()
            ps_s = {
                'ps': ps_j.get('count')
            }

        lki_r = requests.get(lki_api_url)
        if lki_r.status_code == 200:
            lki_j = lki_r.json()
            lki_s = {
                'ps': lki_j.get('count')
            }
        stb_r = requests.get(stb_api_url)
        if stb_r.status_code == 200:
            stb_j = stb_r.json()
            stb_s = {
                'ps': stb_j.get('results').get('view')
            }

        s_data = {**fb_s, **ps_s, **lki_s, **stb_s}
        return s_data
    if isinstance(urls, (list, tuple)):
        raise Exception('传入类型错误')
    if len(urls) > 10:
        raise Exception('url限制10个及以内')
    pool = Pool(max_workers=5)
    results = pool.map(task, urls)
    return json.dumps(list(results))