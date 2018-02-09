#!/usr/bin/python

from collections import Iterable
'''
将list中嵌套list和tuple的所有元素展开都放入同一个list中
'''


def expand(item):
    if not isinstance(item, (list, tuple)):
        raise Exception('{}不是列表或元组'.format(item))
    for x in item:
        if isinstance(x, Iterable) and not isinstance(x, (str, bytes)):
            yield from expand(x)
        else:
            yield x


if __name__ == '__main__':
	lst = [1, 3, [5, [2, ['a', ['qwedsda', ('ws', 'qwer')], 'c']], 90], [18, 20]]
	new = [i for i in expand(lst)]
	print(new)
