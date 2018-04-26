#!/usr/bin/python

class ProTest(object):

	'''
	属性操作:
	作为一门动态语言,对象.属性 = value 是最基本的操作,但是这样的话  少了一些约束
	为了让属性更安全或者说更加规范的操作属性,可以按照下来的来做
	'''
	def __init__(self, param):
		self._param = param
		
	def get_param(self):
		return self._param
		
	def set_param(self, p):
		if not isinstance(p, (int, str)):
			raise Exception('类型错误')
		if p > 100:
			raise EOFError('数据过大')
		self._param = p
		
	def del_param(self):
		del self._param

	param = property(get_param, set_param, del_param)
	
		
# 做法2:直接将方法作为属性操作
class ProTest2(object):
	
	def __init__(self, param):
		self._param = param
		
	# def __str__(self):
		# return self._param
	
	@property
	def param(self):
		return self._param
	
	@param.setter
	def param(self, p):
		if not isinstance(p, (int, str)):
			raise Exception('类型错误')
		if p > 100:
			raise EOFError('数据过大')
		self._param = p
	
	@param.deleter
	def param(self):
		del self._param
		
		
p1 = ProTest2('a')
print(p1._param)
p1.param = 'abc'
print(p1.param)
del param