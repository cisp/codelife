# 先了解下冒泡排序
# 算法: 第一个数和下一个数进行比较 如果前者大那么直接交换位置  所以每一轮都会有一个最大的元素在最后 知道最后排序完成


def bullet_sort(l):
    for i, d in enumerate(l):

        for j, d1 in enumerate(l[:-i]):

            if l[j] > l[j + 1]:
                l[j], l[j + 1] = l[j + 1], l[j]
    print(l)