#!/usr/bin/python
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.http.response import Http404
from django.core.exceptions import PermissionDenied
from django.shortcuts import render

class ExceptionMiddleware(MiddlewareMixin):
	'''
	django自定义异常中间件:
	'''
	def process_exception(self, request, exception):
		if settings.DEBUG:
	            return None
		if isinstance(exception, Http404):
			return None
		if isinstance(exception, PermissionDenied):
			return None
		if not isinstance(exception, Exception):
	        return None
	    return JsonResponse({
	            'success': False,
	            'msg': ''.join(exception.args)
	        }, **{'status': 200})

# ****************************************分割线****************************************

# django自定义403页面
# exp: mysite/url.py中定义处理方法   403页面可以定义在根目录下的templates目录下

def permission_denied(request):
	return render(request, '403.html', {
		# 这里面是你需要返回的数据
		})

urlpatterns = [...]


handler403 = permission_denied
handler404 = page_not_found


# exp: 对应试图文件中,处理返回403的逻辑
#

def index(request, id=None):
	if request.user.id != id:
		raise PermissionDenied()


# exp:自定义404页面更简单, 只用定义一个接收函数,同permission_denied
#
def page_not_found(request):
	return render(request, '404.html', {
		# 这里是你需要返回的数据
		})


# exp: 自定义500同自定义404  不多说