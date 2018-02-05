#!/usr/bin/python
import os
import re
import tweepy


class Twitter(object):
    consumer_key = 'sP7GJsR3JDSLeWOD2xmFuMLX4'
    consumer_secret = 'KWs3NG6ipFHMCjPfozcECWyJx4ow3Ca6W1hRoiMo7RAJgWyxGr'
    request_token = None

    def __init__(self):
        pass

    def authorize(self):
        auth = tweepy.OAuthHandler(self.consumer_key, self.consumer_secret)
        authorization_url = auth.get_authorization_url()
        self.request_token = auth.request_token
        return self.request_token, authorization_url

    def access(self, request_token, oauth_verifier):
        auth = tweepy.OAuthHandler(self.consumer_key, self.consumer_secret)
        auth.request_token = request_token
        try:
            auth.get_access_token(verifier=oauth_verifier)
        except tweepy.TweepError:
            raise Exception('Error! Failed to get access token.')
        oauth_token = auth.access_token
        oauth_secret = auth.access_token_secret
        return {
            'oauth_token': oauth_token,
            'oauth_token_secret': oauth_secret

        }

    def publish(self, oauth_token, oauth_secret, title, filepath, **kwargs):
        if not kwargs.get('proxy'):
            raise Exception('未配置代理！')
        proxies = kwargs['proxy'].split(':')
        ip = proxies[0]
        port = proxies[1]
        user = None
        pswd = None
        if len(proxies) == 4:
            user = proxies[2]
            pswd = proxies[3]
        proxies = {
            "http": "http://{user}:{pswd}@{ip}:{port}".format(ip=ip, port=port, user=user,
                                                              pswd=pswd) if user and pswd else "http://{ip}:{port}".format(
                ip=ip, port=port),
            "https": "https://{user}:{pswd}@{ip}:{port}".format(ip=ip, port=port, user=user,
                                                                pswd=pswd) if user and pswd else "https://{ip}:{port}".format(
                ip=ip, port=port),
        }
        fsize = os.path.getsize(filepath)
        fsize = round(fsize / float(1024 * 1024))
        if fsize > 3:
            raise Exception('该篇文章过大，无法上传至Twitter!')
        auth = tweepy.OAuthHandler(self.consumer_key, self.consumer_secret)
        auth.set_access_token(oauth_token, oauth_secret)

        api = tweepy.API(auth, proxy=proxies.get('https'))
        try:
            upload = api.update_with_media(filepath, status=title)
        except Exception as ex:
            raise Exception('发布文章失败，请联系系统管理员处理')
        id = upload._json.get('id_str')
        url = re.search('https.*', upload._json.get('text')).group()
        return {
            'id': id,
            'url': url
        }



