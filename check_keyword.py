#!/usr/bin/python

import os
import json
import time
import tldextract

from django.conf import settings
from django.core.management.base import BaseCommand

from seo.models.keyword import KeywordMetric
from tenant_schemas.utils import schema_context
from service.kwsearch import KeywordEnum, RankEnum, GoogleBase


class Command(BaseCommand):  # 用法主要是继承BaseCommand 实现父类中的handle方法
    help = 'keyword seo check.  主要是 测试关键词组合方案'
	
	# 需要传多少参数 通过这个方法解析
    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        t = time.strftime('%Y-%m-%d')

        def extract(link):
            return '.'.join(tldextract.extract(link)).strip('.')

        def get_domains(links):
            return list(map(extract, links))

        print('-------------开始轮询测试-------------')
        with schema_context(settings.MAIN_TENANT_SCHEMA):
            keyword = KeywordMetric.objects.filter(func__icontains='keyword')
            moz = KeywordMetric.objects.filter(func__icontains='moz')
            social = KeywordMetric.objects.filter(func__icontains='social')
            results = []
            kw = 'google'
            count = 0
            for k in keyword:
                k.is_active = True
                k_instance = k.func.split('.')[-1]
                k_func = getattr(KeywordEnum, k_instance)
                for m in moz:
                    m.is_active = True
                    m_instance = m.func.split('.')[-1]
                    m_func = getattr(RankEnum, m_instance)
                    for s in social:
                        s.is_active = True
                        s_instance = s.func.split('.')[-1]
                        s_func = getattr(RankEnum, s_instance)
                        results.append({
                            count: {
                                k_instance: False,
                                m_instance: False,
                                s_instance: False,
                            }
                        })
                        k_data = k_func(kw, k)
                        if k_data:
                            first_keyword = k_data[0]['keywords']
                            google = GoogleBase(first_keyword)
                            links = google.main()
                            domains = get_domains(links)
                            m_data = m_func(domains, m)
                            s_data = s_func(domains, s)
                            results[count][count] = {
                                k_instance: True,
                                m_instance: True if m_data else False,
                                s_instance: True if s_data else False
                            }
                        count += 1
            # 测试结果以json文件形式保存
            if not os.path.exists('../seo_check/'):
                os.mkdir('../seo_check/')
            with open("../seo_check/record_{}.json".format(t), "w") as f:
                json.dump(results, f)
        print('-------------测试结束-------------')