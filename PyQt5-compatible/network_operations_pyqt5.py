from headers_pyqt5 import *
import requests
import requests.utils
import json
import logging
import subprocess
import time
from PyQt5.QtCore import QThread, pyqtSignal
from enum import Enum, unique
import platform

proxies = {'http': None, 'https': None}


@unique
class Login_State(Enum):
    login_Successful = 1
    username_password_NOT_SET = 2
    queryString_NOT_FOUND = 3
    cookie_NOT_GET = 4
    post_data_NOT_SEND = 5
    login_Wrong_Unknown = 6


@unique
class Logout_State(Enum):
    logout_Successful = 1
    userIndex_Wrong = 2
    logout_Wrong_Unknown = 6


def login(username, password):
    if username is None or username == '' or password is None or password == '':
        logging.error("[-] Wrong username or passward set.")
        return Login_State.username_password_NOT_SET, None
    publicKeyExponent = '10001'
    publicKeyModules = \
        "94dd2a8675fb779e6b9f7103698634cd400f27a154afa67af6166a43fc26417222a79506d34cacc7641946abda1785b7acf9910ad6" \
        "a0978c91ec84d40b71d2891379af19ffb333e7517e390bd26ac312fe940c340466b4a5d4af1d65c3b5944078f96a1a51a5a53e4bc3" \
        "02818b7c9f63c4a1b07bd7d874cef1c3d4b2f5eb7871"
    redirect_head = get_redirect_headers()
    redirect_url = "http://123.123.123.123"

    try:
        url = requests.get(redirect_url, headers=redirect_head, timeout=1, proxies=proxies, verify=False)
    except Exception as e:
        logging.error(e)
        logging.error(f"Cannot get queryString from {redirect_url}.")
        return Login_State.queryString_NOT_FOUND, None
    url = url.text.split("'")[1]
    queryString = url.split("?")[1]
    headers = get_login_headers(username, password)
    formdata = {
        'userId': username,
        'password': password,
        'service': '',
        'queryString': queryString,
        'operatorPwd': '',
        'operatorUserId': '',
        'validcode': '',
        'passwordEncrypt': 'false'
    }

    content_list = []
    for key in formdata:
        content = ''
        content += key
        content += '='
        content += formdata[key]
        content_list.append(content)

    content = '&'.join(content_list)
    try:
        cookie_response = requests.get(url, headers=headers, proxies=proxies)
    except Exception as e:
        logging.error(e)
        logging.error(f"Cannot get cookie from {url}.")
        return Login_State.cookie_NOT_GET, None
    cookie = requests.utils.dict_from_cookiejar(cookie_response.cookies)['JSESSIONID']
    headers['Cookie'] = headers['Cookie'].replace('C19A16116BF2C50DE7EDA5EFE981AEEE', cookie)
    headers['Content-Length'] = str(len(content))
    try:
        response = requests.post('http://192.168.50.3:8080/eportal/InterFace.do?method=login', data=formdata,
                                 headers=headers, proxies=proxies, timeout=1)
    except Exception as e:
        logging.error(e)
        logging.error("Cannot post data to http://192.168.50.3:8080/eportal/InterFace.do?method=login.")
        return Login_State.post_data_NOT_SEND, None
    try:
        data = response.content.decode('utf-8', 'ignore')
        data = json.loads(data)
    except Exception as e:
        logging.error(e)
        logging.error("Cannot parse data.")
        return Login_State.login_Wrong_Unknown, None
    if data["result"] == "success":
        logging.info("[+] Login Successful")
        return Login_State.login_Successful, data['userIndex']
    else:
        return Login_State.login_Wrong_Unknown, None


def get_index(username, password):
    headers = get_login_headers(username, password)
    try:
        response = requests.get('http://192.168.50.3:8080//eportal/gologout.jsp',
                                headers=headers, proxies=proxies, timeout=1)
        return response.url.split('userIndex=')[1]
    except Exception as e:
        logging.error(e)
        logging.error("Cannot get data from http://192.168.50.3:8080//eportal/gologout.jsp.")
        return None


def logout(username, password, user_index):
    headers = get_logout_headers(password)
    formdata = {
        'userIndex': user_index
    }

    content_list = []
    for key in formdata:
        content = ''
        content += key
        content += '='
        content += formdata[key]
        content_list.append(content)

    content = '&'.join(content_list)
    headers['Content-Length'] = str(len(content))

    try:
        response = requests.post('http://192.168.50.3:8080/eportal/InterFace.do?method=logout', data=formdata,
                                 headers=headers, proxies=proxies, timeout=1)
    except Exception as e:
        logging.error(e)
        logging.error("Cannot post data to http://192.168.50.3:8080/eportal/InterFace.do?method=logout.")
        return Logout_State.userIndex_Wrong
    try:
        data = response.content.decode('utf-8', 'ignore')
        data = json.loads(data)
    except Exception as e:
        logging.error(e)
        logging.error("Cannot parse data.")
        return Logout_State.logout_Wrong_Unknown
    if data["result"] == "success":
        logging.info("[+] Logout Successful.")
        return Logout_State.logout_Successful
    else:
        return Logout_State.logout_Wrong_Unknown


class NetworkTest(QThread):
    network_flag = pyqtSignal(bool)

    def __init__(self):
        super(NetworkTest, self).__init__()

    def run(self):
        not_support_flag = False
        while True:
            try:
                ip = '202.114.0.131'
                if platform.system() == "Windows":
                    ret = subprocess.call("ping -n 1 {}".format(ip), stdout=subprocess.DEVNULL, shell=True)
                elif platform.system() == "Linux":
                    ret = subprocess.call("ping -c 1 {}".format(ip), stdout=subprocess.DEVNULL, shell=True)
                else:
                    if not not_support_flag:
                        logging.error("[-] System type does not support.")
                    not_support_flag = True
                    continue
                if ret == 0:
                    self.network_flag.emit(True)
                else:
                    self.network_flag.emit(False)
                time.sleep(0.5)
            except Exception as e:
                logging.error(e)
                self.network_flag.emit(False)
                time.sleep(0.5)
                continue