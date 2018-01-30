class UrlBrowser(object):
    browser = None

    def __init__(self, url, proxies=None):
        service_args = None
        if proxies:
            proxies = proxies.split(':')
            ip = proxies[0]
            port = proxies[1]
            service_args = [
                '--proxy={}:{}'.format(ip, port),
                '--proxy-type=http',
                '--ssl-protocol=any',
                '--ignore-ssl-errors=true'
            ]
            if len(proxies) == 4:
                user = proxies[2]
                pswd = proxies[3]
                service_args += [
                    '--proxy-auth={}:{}'.format(user, pswd),
                ]
        self.browser = Browser('phantomjs', service_args=service_args)
        self.browser.driver.maximize_window()
        self.browser.visit(url)

    def __enter__(self):
        return self.browser

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.browser.quit()


class Diigo(object):

    def __init__(self):
        pass

    def publish(self, post_url, title, **kwargs):
        # if not kwargs.get('proxy'):
        #     raise Exception('未配置代理')
        login_url = 'https://www.diigo.com/sign-in'
        with UrlBrowser(login_url) as browser:
            if browser.is_element_present_by_id('loginButton', wait_time=15):
                browser.fill('Username', self.username)
                browser.fill('password', self.password)
                browser.click_link_by_id('loginButton')
            else:
                raise Exception('当前网络发生错误！')
            time.sleep(5)
            if browser.is_element_present_by_xpath('//*[@id="library"]/div[1]/div/div/div/span[2]/div[2]', wait_time=5):
                browser.find_by_xpath('//*[@id="library"]/div[1]/div/div/div/span[2]/div[2]').first.click()

            time.sleep(2)
            browser.find_by_xpath('//*[@id="library"]/div[1]/div/div/div/span[2]/div[1]/div[1]').first.click()
            time.sleep(5)
            browser.driver.find_element_by_xpath(
                '//*[@id="AppWrapper"]/div[3]/span[2]/div/div/div/div[2]/div/div[1]/div/input').send_keys(post_url)

            time.sleep(1)
            browser.driver.find_element_by_xpath(
                '//*[@id="AppWrapper"]/div[3]/span[2]/div/div/div/div[2]/div/div[2]/button').click()
            time.sleep(5)
            browser.driver.find_element_by_xpath(
                '//*[@id="AppWrapper"]/div[3]/span[2]/div/div/div/div[2]/div/div[2]/div[1]/div/input').clear()

            time.sleep(1)
            browser.driver.find_element_by_xpath(
                '//*[@id="AppWrapper"]/div[3]/span[2]/div/div/div/div[2]/div/div[2]/div[1]/div/input').send_keys(title)
            time.sleep(1)
            browser.driver.find_element_by_xpath(
                '//*[@id="AppWrapper"]/div[3]/span[2]/div/div/div/div[2]/div/div[2]/div[6]/button').click()
            time.sleep(3)
            browser.driver.find_element_by_xpath(
                '//*[@id="library"]/div[2]/div[2]/div[2]/div[2]/div/span/div/div[1]/div[2]/div/label/span/i').click()
            time.sleep(1)
            browser.driver.find_element_by_xpath(
                '//*[@id="library"]/div[2]/div[2]/div[2]/div[2]/div/span/div/div[1]/div[2]/div/div/div[3]').click()
            time.sleep(3)
            result_url = browser.driver.find_element_by_xpath(
                '//*[@id="AppWrapper"]/div[3]/span[2]/div/div/div/div[2]/div/div/div/div[1]/div/input').get_attribute(
                'value')
            if result_url:
                return {
                    'id': result_url.split('/')[-1],
                    'url': result_url
                }
            else:
                raise Exception('发布失败')


def publish_article(title, content):
    url = 'https://northant520.wordpress.com/'
    username = 'ouyangrex@outlook.com'
    password = 'ouyang1990'
    from urllib.parse import urljoin
    from wordpress_xmlrpc import Client, WordPressPost
    from wordpress_xmlrpc.methods import posts
    from wordpress_xmlrpc.exceptions import InvalidCredentialsError

    wp = Client(urljoin(url, 'xmlrpc.php'), username, password)

    wppost = WordPressPost()
    wppost.title = title
    wppost.content = content
    wppost.post_status = 'publish'
    try:
        id = wp.call(posts.NewPost(wppost))
    except InvalidCredentialsError:
        raise Exception('账户名或密码错误')   
    url = wp.call(posts.GetPost(id)).link
    diigo = Diigo()
    diigo.publish(url, title)


if __name__ == '__main__':
    publish_article('for test!', '<p>to be a better codeman</p>')