import requests
from bs4 import BeautifulSoup
username = '15618620929@163.com'
password = 'xxxxxxxxxxxxxxxx'
base_url = 'https://github.com/'
login_url = 'https://github.com/login'
session_url = 'https://github.com/session'
SESSION = requests.session()
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0'
}


def get_token():
    resp = SESSION.get(login_url, headers=headers)
    if resp.status_code != 200:
        raise Exception('Maybe your ip is denied or your network is unnormal')
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find(attrs={'name': 'authenticity_token'}).get('value')
    return str(token)


def login():
    token = get_token()
    form = {
        'login': username,
        'password': password,
        'commit': 'Sign in',
        'authenticity_token': token,
        'utf8': '%E2%9C%93'
    }
    SESSION.post(url=session_url, data=form, headers=headers)
    rep = SESSION.get(base_url, headers=headers)
    print(rep.text)


if __name__ == '__main__':
    login()


