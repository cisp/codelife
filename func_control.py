#!/usr/bin/python
# -*- coding: utf-8 -*-

import time
from django.core.cache import cache


class CallTimesLimit(object):
    def __init__(self, max, time):
        self.__max = max  # 最大调用次数
        self.__time = time  # 缓存超时时间
        self.__count = 0

    def __call__(self, fun):
        self.__fun = fun
        return self.__proxy

    def __proxy(self, *args, **kwargs):
        key = self.__fun.__name__
        USED_CACHE = 'keyword//{}'.format(key)
        used_count = cache.get(USED_CACHE) or 0
        self.__count = used_count
		
        if self.__count < self.__max:
            self.__count += 1
            cache.set(USED_CACHE, self.__count, timeout=self.__time)  # 缓存更新调用次数
            return self.__fun(*args, **kwargs)
        else:
            raise Exception(
                "The function {} has been called {} times in {} seconds ".format(
                    self.__fun.__name__, self.__max, self.__time))
					
					
# 测试:限制10s内 函数最多调用5次
@CallTimesLimit(5, 10)
def test():
	print('call me, call me!')
	

if __name__ == '__main__':
	test()
	time.sleep(2)
	test()
	time.sleep(2)
	test()
	time.sleep(2)
	test()
	# time.sleep(2)
	time.sleep(5)
	test()
	
	
	