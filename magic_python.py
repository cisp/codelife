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
	
	
# 最简单的单例 -- 重写__new__方法

class singleton(object):

	_single = None
	
	def __new__(cls, *arg, **args):
		if not cls._single:
			cls._single = super().__new__(cls)
		return cls._single
		
	def __init__(self, name):
		self.name = name
	
	def get_name(self):
		return self.name
# test
s1 = singleton('single1')
s2 = singleton('single2')

# 下面的结果:都是
s1.fprint()
s2.fprint()


# 简单类装饰器 计算某个函数调用次数:重点是里面的__call__方法   
# __call__方法存在的意义就是是对象成为可调用对象,例如:
# a = A();  a() ---> a就是可调用对象
class Counter(object):

    def __init__(self, func):
        self.count = 0
        self.func = func

    def __call__(self, *args, **kwargs):
        self.count += 1
        return self.func(*args, **kwargs)


@Counter
def foo():
    pass


for i in range(10):
    foo()

print(foo.count)  # foo 是Count的对象
print(foo.__class__.__name__)


# 简单自己做一个整数迭代器
# 核心: 必须实现的两个方法__iter__ & __next__
# for循环  就是不断的调用__next__方法  直到遇到异常才终止
class MyRange(object):

	def __init__(self, num):
		self.count = 0
		self.num = num
		
	def __iter__(self):
		return self  # 返回迭代对象
		
	def __next__(self):
		if self.count <= self.num:
			count = self.count 
			self.counnt += 1
			return count
		else:
			raise StopIteration('已经是最后一个元素了')
			

# 上下文管理器
# 与其叫管理器 不如称之为上下文协议更为恰当
# 所谓协议 就是约定好的  python中上下文协议需要实现两个方法: __enter__ and __exit__,例如:

class my_open(object):
	
	def __init__(self, filepath, mode):
		self._filepath = filepath
		self._mode = mode
	
	def __enter__(self, *args, **kwargs):
		if not os.path.isexsit(self._filepath):
			os.mkdir(self._filepath)
		self.f = open(self._filepath, self._mode)
		return self.f
		
	def __exit__(self, *args, **kwargs):
		if self.f:
			self.f.close()
			
# 上面是实现一个极简版的文件上下文协议,使用标准 with ... as ...,例如：

with my_open('your file path') as f:
	f.read()

	
# python提供另外一装饰器的方式,更加方便，如:
from contextlib import contextmanager
@contextmanager
def my_open(path, mode):
	f = open(path, mode)
	yield f
	f.close()
	
with my_open(path, mode) as f:  # python牛逼!
	f.read()
	
# python解析txt/excel/csv
class KeywordFile(object):
    '''
    解析上传的关键词文件
    '''
    def __init__(self, filename):
        self._filename = filename

    def __call__(self, *args, **kwargs):
        suffix = self.is_valid_file()
        if not suffix:
            raise Exception('上传文件不符合文件规则')
        else:
            if suffix == 'xls' or suffix == 'xlsx':
                result = self.handle_excel(suffix)
            elif suffix == 'csv':
                result = self.handle_csv()
            else:
                result = self.handle_txt()
        return json.dumps(result)

    def is_valid_file(self):
        valid_suffix = ['txt', 'xls', 'xlsx', 'csv']

        file_suffix = self._filename.split('.')[-1]

        if file_suffix in valid_suffix:
            return file_suffix
        else:
            return False

    def handle_excel(self, suffix):
        result = []
        wb = openpyxl.load_workbook(self._filename) if suffix == 'xlsx' else xlrd.open_workbook(self._filename)
        # 默认第一个sheet
        ws = wb.active
        for row in ws.rows:
            for cell in row:
                result.append(cell.value)
        return result

    def handle_txt(self):
        with open(self._filename, 'r') as f:
            result = [res.strip(' ') for res in f.read().split('\n') if res]
        return result

    def handle_csv(self):
        result = []
        with open(self._filename, 'r') as f:
            csv_reader = csv.reader(f)
            for row in csv_reader:
                result.append(row[0])
        return result
	

# python3 特有  拆箱  只能说真的很好用一个新特性
l = [1, 2, 3, 4, 5]
a, b, *c = l  # print: a = 1, b = 2, c = [3, 4, 5]





		
