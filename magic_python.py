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