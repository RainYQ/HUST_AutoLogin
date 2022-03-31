def get_login_headers(username, password, office_flag):
    group = '%E5%8A%9E%E5%85%AC%E5%8C%BA%E7%94%A8%E6%88%B7%E7%BB%84' if office_flag else \
        "%E5%8D%8E%E4%B8%AD%E7%A7%91%E6%8A%80%E5%A4%A7%E5%AD%A6"
    headers = {
        'Host': '192.168.50.3:8080',
        'Connection': 'keep-alive',
        'Content-Length': '895',
        'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 '
            'Safari/537.36 Edg/96.0.1054.62',
        'DNT': '1',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Origin': 'http://192.168.50.3:8080',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7,en-GB;q=0.6',
        'Cookie':
            'EPORTAL_COOKIE_OPERATORPWD=; '
            'EPORTAL_COOKIE_SERVER=; '
            'EPORTAL_COOKIE_DOMAIN=; '
            'EPORTAL_COOKIE_SAVEPASSWORD=true; '
            # urlEncode: 请选择服务
            'EPORTAL_COOKIE_SERVER_NAME=%E8%AF%B7%E9%80%89%E6%8B%A9%E6%9C%8D%E5%8A%A1; '
            # urlEncode: 华中科技大学
            f'EPORTAL_USER_GROUP={group}; '
            'EPORTAL_COOKIE_USERNAME=' + username + '; ' +
            'EPORTAL_COOKIE_PASSWORD=' + password + '; ' +
            'JSESSIONID=C19A16116BF2C50DE7EDA5EFE981AEEE'
    }
    return headers


def get_redirect_headers():
    headers = {
        'Host': '123.123.123.123',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'DNT': '1',
        'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 '
            'Safari/537.36 Edg/96.0.1054.62',
        'Accept':
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
            'application/signed-exchange;v=b3;q=0.9',
        'Referer': 'http://192.168.50.3:8080/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7,en-GB;q=0.6'
    }
    return headers


def get_logout_headers(password, office_flag):
    group = '%E5%8A%9E%E5%85%AC%E5%8C%BA%E7%94%A8%E6%88%B7%E7%BB%84' if office_flag else \
        "%E5%8D%8E%E4%B8%AD%E7%A7%91%E6%8A%80%E5%A4%A7%E5%AD%A6"
    headers = {
        'Host': '192.168.50.3:8080',
        'Connection': 'keep-alive',
        'Content-Length': '128',
        'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 '
            'Safari/537.36 Edg/96.0.1054.62',
        'DNT': '1',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Origin': 'http://192.168.50.3:8080',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7,en-GB;q=0.6',
        'Cookie':
            'EPORTAL_COOKIE_OPERATORPWD=; '
            'EPORTAL_COOKIE_SERVER=; '
            'EPORTAL_COOKIE_DOMAIN=; '
            'EPORTAL_COOKIE_SAVEPASSWORD=true; '
            'EPORTAL_COOKIE_USERNAME=; '
            'EPORTAL_COOKIE_NEWV=true; '
            'EPORTAL_COOKIE_PASSWORD=' + password + '; ' +
            'EPORTAL_AUTO_LAND=; '
            # urlEncode: 请选择服务
            'EPORTAL_COOKIE_SERVER_NAME=; '
            # urlEncode: 华中科技大学
            f'EPORTAL_USER_GROUP={group}; '
            'JSESSIONID=3AC4520F2F846C4C06ABE15B961F620C; '
            'JSESSIONID=4E728295B7F567ECECB0D586F1F5CBC2'
    }
    return headers
