#!/usr/bin/python
# -*- coding: utf-8 -*-

from django.apps import apps


def getmodelfield(appname, modelname, verbose=False):
    '''
    :param appname: 应用名称
    :param modelname: 表名
    :param verbose: 取verbose_name标识
    :return: verbose_name或者列名
    '''
    modelobj = apps.get_model(appname, modelname)
    verboses = {}
    colum = []
    for field in modelobj._meta.fields:
        if verbose:
            verboses[field.name] = field.verbose_name.decode('utf-8')
        else:
            colum.append(field.name)
    if verbose:
        return verboses
    else:
        return colum