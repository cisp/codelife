#!/usr/bin/python

import json
from urllib3.filepost import encode_multipart_formdata
from urllib import parse, request
from lxml import etree
import codecs
import httplib2
import oauth2 as oauth
from user_agent import generate_user_agent

__version__ = '0.3.2'


class FlickrAPIError(Exception):
    """ Generic error class, catch-all for most Tumblpy issues.

        from Tumblpy import FlickrAPIError, FlickrAuthError
    """
    def __init__(self, msg, error_code=None):
        self.msg = msg
        self.code = error_code
        if error_code is not None and error_code < 100:
            raise FlickrAuthError(msg, error_code)

    def __str__(self):
        return repr(self.msg)


class FlickrAuthError(FlickrAPIError):
    """ Raised when you try to access a protected resource and it fails due to some issue with your authentication. """
    def __init__(self, msg, error_code=None):
        self.msg = msg
        self.code = error_code

    def __str__(self):
        # return repr(self.msg)


class FlickrAPI(object):
    def __init__(self, api_key=None, api_secret=None, oauth_token=None, oauth_token_secret=None, callback_url=None, headers=None, client_args=None, opener=None):
        if not api_key or not api_secret:
            raise Exception('Please supply an api_key and api_secret.')

        self.api_key = api_key
        self.api_secret = api_secret
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.callback_url = callback_url
        self.opener = opener
        self.api_base = 'https://api.flickr.com/services'
        self.up_api_base = 'https://up.flickr.com/services'
        self.rest_api_url = '%s/rest' % self.api_base
        self.upload_api_url = '%s/upload/' % self.up_api_base
        self.replace_api_url = '%s/replace/' % self.up_api_base
        self.request_token_url = 'https://www.flickr.com/services/oauth/request_token'
        self.access_token_url = 'https://www.flickr.com/services/oauth/access_token'
        self.authorize_url = 'https://www.flickr.com/services/oauth/authorize'

        self.headers = headers
        if self.headers is None:
            self.headers = {'User-agent': generate_user_agent()}
        self.consumer = None
        self.token = None

        client_args = client_args or {}

        if self.api_key is not None and self.api_secret is not None:
            self.consumer = oauth.Consumer(self.api_key, self.api_secret)

        if self.oauth_token is not None and self.oauth_token_secret is not None:
            self.token = oauth.Token(oauth_token, oauth_token_secret)

        # Filter down through the possibilities here - if they have a token, if they're first stage, etc.
        if self.consumer is not None and self.token is not None:
            self.client = oauth.Client(self.consumer, self.token, **client_args)
        elif self.consumer is not None:
            self.client = oauth.Client(self.consumer, **client_args)
        else:
            # If they don't do authentication, but still want to request unprotected resources, we need an opener.
            self.client = httplib2.Http(**client_args)

    def api_request(self, endpoint=None, method='GET', params={}, files=None, replace=False):
        self.headers.update({'Content-Type': 'application/json'})
        self.headers.update({'Content-Length': '0'})

        if endpoint is None and files is None:
            raise FlickrAPIError('Please supply an API endpoint to hit.')

        qs = {
            'format': 'json',
            'nojsoncallback': 1,
            'method': endpoint,
            'api_key': self.api_key
        }

        if method == 'POST':

            if files is not None:
                # To upload/replace file, we need to create a fake request
                # to sign parameters that are not multipart before we add
                # the multipart file to the parameters...
                # OAuth is not meant to sign multipart post data
                http_url = self.replace_api_url if replace else self.upload_api_url
                faux_req = oauth.Request.from_consumer_and_token(self.consumer,
                                                                 token=self.token,
                                                                 http_method="POST",
                                                                 http_url=http_url,
                                                                 parameters=params)

                faux_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(),
                                      self.consumer,
                                      self.token)

                all_upload_params = dict(parse.parse_qsl(faux_req.to_postdata()))

                # For Tumblr, all media (photos, videos)
                # are sent with the 'data' parameter
                all_upload_params['photo'] = (files.name, files.read())
                body, content_type = encode_multipart_formdata(all_upload_params)

                self.headers.update({
                    'Content-Type': content_type,
                    'Content-Length': str(len(body))
                })
                request.install_opener(self.opener)
                req = request.Request(http_url, body, self.headers)
                req = request.urlopen(req)
                # After requests is finished, delete Content Length & Type so
                # requests after don't use same Length and take (i.e 20 sec)
                del self.headers['Content-Type']
                del self.headers['Content-Length']

                # If no error, assume response was 200
                resp = {'status': 200}

                content = req.read()
                content = etree.XML(content)

                stat = content.get('stat') or 'ok'

                if stat == 'fail':
                    if content.find('.//err') is not None:
                        code = content.findall('.//err[@code]')
                        msg = content.findall('.//err[@msg]')

                        if len(code) > 0:
                            if len(msg) == 0:
                                msg = 'An error occurred making your Flickr API request.'
                            else:
                                msg = msg[0].get('msg')

                            code = int(code[0].get('code'))

                            content = {
                                'stat': 'fail',
                                'code': code,
                                'message': msg
                            }
                else:
                    photoid = content.find('.//photoid')
                    if photoid is not None:
                        photoid = photoid.text

                    content = {
                        'stat': 'ok',
                        'photoid': photoid
                    }

            else:
                url = self.rest_api_url + '?' + parse.urlencode(qs) + '&' + parse.urlencode(params)
                resp, content = self.client.request(url, 'POST', headers=self.headers)
        else:
            params.update(qs)
            resp, content = self.client.request('%s?%s' % (self.rest_api_url, parse.urlencode(params)), 'GET', headers=self.headers)

        # try except for if content is able to be decoded
        try:
            if type(content) != dict:
                content = json.loads(content.decode('utf-8'))
        except ValueError:
            raise FlickrAPIError('Content is not valid JSON, unable to be decoded.')

        status = int(resp['status'])
        if status < 200 or status >= 300:
            raise FlickrAPIError('Flickr returned a Non-200 response.', error_code=status)

        if content.get('stat') and content['stat'] == 'fail':
            raise FlickrAPIError('Flickr returned error code: %d. Message: %s' % \
                                (content['code'], content['message']),
                                error_code=content['code'])

        return dict(content)

    def get(self, endpoint=None, params=None):
        params = params or {}
        return self.api_request(endpoint, method='GET', params=params)

    def post(self, endpoint=None, params=None, files=None, replace=False):
        params = params or {}
        return self.api_request(endpoint, method='POST', params=params, files=files, replace=replace)


class OAuthBase(object):
    request_token_url = ''
    authorize_url = ''
    access_token_url = ''

    consumer_key = ''
    consumer_secret = ''
    oauth_token = ''
    oauth_secret = ''

    def __init__(self):
        pass

    def authorize(self):

        consumer = oauth.Consumer(key=self.consumer_key, secret=self.consumer_secret)
        client = oauth.Client(consumer)
        resp, content = client.request(self.request_token_url, "GET")
        request_token = dict(parse.parse_qsl(content.decode()))
        return request_token, '{authorize_url}?oauth_token={oauth_token}'.format(
            authorize_url=self.authorize_url,
            oauth_token=request_token['oauth_token'])

    def access(self, request_token, oauth_verifier):
        consumer = oauth.Consumer(key=self.consumer_key, secret=self.consumer_secret)
        token = oauth.Token(request_token['oauth_token'],
                            request_token['oauth_token_secret'])
        token.set_verifier(oauth_verifier)
        client = oauth.Client(consumer, token)
        resp, content = client.request(self.access_token_url, "POST")
        access_token = dict(parse.parse_qsl(content.decode()))
        return access_token


class Plurk(OAuthBase):

    def __init__(self):
        self.request_token_url = 'https://www.plurk.com/OAuth/request_token'
        self.authorize_url = 'https://www.plurk.com/OAuth/authorize'
        self.access_token_url = 'https://www.plurk.com/OAuth/access_token'

        self.consumer_key = 'x3mNTUc7un4O'
        self.consumer_secret = 'YWJlm1b4XfWIZ3m9WkUgmYXPSuRi5tjh'
        super().__init__()

    def publish(self, filepath, **kwargs):
        if not kwargs.get('proxy'):
            raise Exception('未配置代理')

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
        plurk = PlurkAPI(key=self.consumer_key, secret=self.consumer_secret, proxies=proxies)
        plurk.authorize(access_key=self.oauth_token, access_secret=self.oauth_secret)
        add_picture = plurk.callAPI('/APP/Timeline/uploadPicture', fpath=filepath)
        url = add_picture.get('full')
        id = 'plurk'
        return {
            'id': id,
            'url': url
        }