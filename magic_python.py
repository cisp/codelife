#!/usr/bin/python

# 将两个dict合并(python > 3.4) 效率奇高
# 这个语法不仅合并  还能去重(如果key和value的值一致的话) 如果key相同,会将第一个元素中的key-value移除  保留最后元素的
d1 = {'a': 1}
d2 = {'b': 2}
d = {**d1, **d2}

# 关于str和repr说明:两个都是bulitins函数  str是返回human可读的  repr是返回解释器可识别的

from datetime import datetime

now = datetime.now()

print(str(now))
print(repr(now))

# dict排序 可根据key/value/key or value length and so on

d1 = {'n': 21, 'h': 'sd', 'a': 213}

d1 = sorted(d1.items(), key=lambda d: d[0])  # sort by key

# 上面的lammbda函数可以使用operator.itemgger代替

import operator

d1 = sorted(d1.items(), key=operator.itemgger(1))  # sort by value

from collections import OrderedDict

# return OrderedDict object(imp by dict)
od = OrderedDict(d1)  # 最直接的方法  使用轮子 这个轮子牛逼在于可以按照排序后的顺序添加

od['b'] = 123  # 'b': 123 在元素最末尾 保证顺序


# 动态  真正的动态:所谓动态 就是一边做的时候  一边获取  python 厉害就厉害在这里(我是觉得真的强)
# 1.根据对象 获取对象的属性(这个简单  动态语言都有的特性)
class A:
    def __init__(self, name):
        self.name = name

    def __call__(self, *args, **kwargs):
        self.name = self.name

    def test(self):
        print('for test!')

    def hello(self):
        print('hello world!')


a = A('python')
print(a.__class__.__name__)  # 获取当前类名
print(a.__dict__)  # 获取字段属性
hasattr(a, 'hello')
getattr(a, 'hello')  # 这是真正的神器 如果对象a有属性hello 那就获取这个属性


# 下面就厉害了 动态获取模块中的属性
import importlib

m1 = importlib.import_module('test')
if hasattr(m1, 'A'):
    print('模块test中存在属性A')
