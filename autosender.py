import requests
import requests.utils
import logging
import sys
import json
import os
from enum import Enum, unique
import time
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QCoreApplication, QVariant
from PyQt6.QtGui import QPixmap, QColor, QIcon, QAction, QPainter
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QHBoxLayout, QMainWindow, QWidget, QVBoxLayout, \
    QPushButton, QSystemTrayIcon, QMenu, QMessageBox, QCheckBox, QComboBox

os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(os.path.dirname(sys.argv[0]), 'cacert.pem')

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S %p"

logging.basicConfig(filename='run.log', level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)

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
        logging.warning("[*] Wrong username or passward set.")
        return Login_State.username_password_NOT_SET, None
    publicKeyExponent = '10001'
    publicKeyModules = \
        "94dd2a8675fb779e6b9f7103698634cd400f27a154afa67af6166a43fc26417222a79506d34cacc7641946abda1785b7acf9910ad6" \
        "a0978c91ec84d40b71d2891379af19ffb333e7517e390bd26ac312fe940c340466b4a5d4af1d65c3b5944078f96a1a51a5a53e4bc3" \
        "02818b7c9f63c4a1b07bd7d874cef1c3d4b2f5eb7871"

    redirect_url = "http://123.123.123.123"
    redirect_head = {
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

    try:
        url = requests.get(redirect_url, headers=redirect_head, timeout=1, proxies=proxies, verify=False)
    except Exception as e:
        logging.warning(e)
        return Login_State.queryString_NOT_FOUND, None
    url = url.text.split("'")[1]
    queryString = url.split("?")[1]
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
            'EPORTAL_COOKIE_SERVER_NAME=%E8%AF%B7%E9%80%89%E6%8B%A9%E6%9C%8D%E5%8A%A1; '
            'EPORTAL_USER_GROUP=%E5%8D%8E%E4%B8%AD%E7%A7%91%E6%8A%80%E5%A4%A7%E5%AD%A6; '
            'EPORTAL_COOKIE_USERNAME=' + username + '; ' +
            'EPORTAL_COOKIE_PASSWORD=' + password + '; ' +
            'JSESSIONID=C19A16116BF2C50DE7EDA5EFE981AEEE'
    }

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
        logging.warning(e)
        return Login_State.cookie_NOT_GET, None
    cookie = requests.utils.dict_from_cookiejar(cookie_response.cookies)['JSESSIONID']
    headers['Cookie'] = headers['Cookie'].replace('C19A16116BF2C50DE7EDA5EFE981AEEE', cookie)
    headers['Content-Length'] = str(len(content))
    try:
        response = requests.post('http://192.168.50.3:8080/eportal/InterFace.do?method=login', data=formdata,
                                 headers=headers, proxies=proxies, timeout=1)
    except Exception as e:
        logging.warning(e)
        return Login_State.post_data_NOT_SEND, None
    data = response.content.decode('gb18030', 'ignore')
    data = json.loads(data)
    if data["result"] == "success":
        logging.info("[*] Login Successful")
        return Login_State.login_Successful, data['userIndex']
    else:
        return Login_State.login_Wrong_Unknown, None


def logout(username, password, user_index):
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
            'EPORTAL_COOKIE_SERVER_NAME=%E8%AF%B7%E9%80%89%E6%8B%A9%E6%9C%8D%E5%8A%A1; '
            'EPORTAL_USER_GROUP=%E5%8D%8E%E4%B8%AD%E7%A7%91%E6%8A%80%E5%A4%A7%E5%AD%A6; '
            'JSESSIONID=3AC4520F2F846C4C06ABE15B961F620C; '
            'JSESSIONID=4E728295B7F567ECECB0D586F1F5CBC2'
    }

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
        logging.warning(e)
        return Logout_State.userIndex_Wrong
    data = response.content.decode('gb18030', 'ignore')
    data = json.loads(data)
    if data["result"] == "success":
        logging.info("[*] Logout Successful")
        return Logout_State.logout_Successful
    else:
        return Logout_State.logout_Wrong_Unknown


class NetworkTest(QThread):
    network_flag = pyqtSignal(bool)

    def __init__(self):
        super(NetworkTest, self).__init__()

    def run(self):
        headers = {
            'User-Agent':
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62',
        }
        while True:
            try:
                status = requests.get("https://www.baidu.com",
                                      headers=headers, timeout=1,
                                      proxies=proxies).status_code
            except Exception as e:
                logging.info(e)
                self.network_flag.emit(False)
                time.sleep(0.5)
                continue
            if status == 200:
                self.network_flag.emit(True)
            else:
                self.network_flag.emit(False)
            time.sleep(0.5)


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.network_out_flag = 0
        self.remember = False
        self.username = []
        self.password = []
        self.userindex = []

        self.first_network_detect = True
        self.keep_login_flag = False
        self.password_show_flag = False

        self.setWindowTitle("AutoLogin")
        self.setFixedSize(300, 400)

        self.app_svg = QSvgRenderer(r"icons/app.svg")
        self.app_pixmap = QPixmap(128, 128)
        self.app_pixmap.fill(QColor(0, 0, 0, 0))
        self.app_painter = QPainter(self.app_pixmap)
        self.app_svg.render(self.app_painter)
        self.app_icon = QIcon(self.app_pixmap)
        self.setWindowIcon(self.app_icon)

        self.statusBar().setSizeGripEnabled(False)
        self.setWindowFlags(Qt.WindowType.WindowMinimizeButtonHint & Qt.WindowType.WindowCloseButtonHint)

        self.tray = QSystemTrayIcon()
        self.tray_svg = QSvgRenderer(r"icons/网络.svg")
        self.tray_pixmap = QPixmap(128, 128)
        self.tray_pixmap.fill(QColor(0, 0, 0, 0))
        self.tray_painter = QPainter(self.tray_pixmap)
        self.tray_svg.render(self.tray_painter)
        self.tray_icon = QIcon(self.tray_pixmap)
        self.tray.setIcon(self.tray_icon)

        self.show_svg = QSvgRenderer(r"icons/显示.svg")
        self.show_pixmap = QPixmap(128, 128)
        self.show_pixmap.fill(QColor(0, 0, 0, 0))
        self.show_painter = QPainter(self.show_pixmap)
        self.show_svg.render(self.show_painter)
        self.show_action = QAction(QIcon(self.show_pixmap), "&Show", self, triggered=self.re_show)
        self.exit_svg = QSvgRenderer(r"icons/退出.svg")
        self.exit_pixmap = QPixmap(128, 128)
        self.exit_pixmap.fill(QColor(0, 0, 0, 0))
        self.exit_painter = QPainter(self.exit_pixmap)
        self.exit_svg.render(self.exit_painter)
        self.quit_action = QAction(QIcon(self.exit_pixmap), "&Quit", self, triggered=self.re_exit)
        self.trayMenu = QMenu(self)
        self.trayMenu.addAction(self.show_action)
        self.trayMenu.addSeparator()
        self.trayMenu.addAction(self.quit_action)
        self.tray.setContextMenu(self.trayMenu)
        self.tray.show()

        self.tray.activated[QSystemTrayIcon.ActivationReason].connect(self.icon_activated)

        self.vbox = QVBoxLayout()
        self.vbox.addStretch(1)

        self.username_combobox = QComboBox()
        self.username_combobox.setEditable(True)
        self.username_combobox.setMaxVisibleItems(3)

        self.username_label = QLabel()
        self.username_label.setText("账号：")
        self.username_combobox.lineEdit().setPlaceholderText("请输入账号")
        self.username_combobox.setMinimumWidth(160)

        self.username_group = QWidget()
        self.username_group_layout = QHBoxLayout()
        self.username_group_layout.addWidget(self.username_label)
        self.username_group_layout.addWidget(self.username_combobox)

        self.username_group.setLayout(self.username_group_layout)

        self.vbox.addWidget(self.username_group)

        self.password_text = QLineEdit()
        self.password_text.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_text.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.password_show_svg = QSvgRenderer(r"icons/解锁.svg")
        self.password_show_pixmap = QPixmap(32, 32)
        self.password_show_pixmap.fill(QColor(0, 0, 0, 0))
        self.password_show_painter = QPainter(self.password_show_pixmap)
        self.password_show_svg.render(self.password_show_painter)
        self.password_hide_svg = QSvgRenderer(r"icons/锁定.svg")
        self.password_hide_pixmap = QPixmap(32, 32)
        self.password_hide_pixmap.fill(QColor(0, 0, 0, 0))
        self.password_hide_painter = QPainter(self.password_hide_pixmap)
        self.password_hide_svg.render(self.password_hide_painter)
        self.password_change_button = QPushButton()
        self.password_change_button.setFixedSize(16, 16)
        self.password_change_button.setToolTip("Show/Hide")

        self.password_show_icon = QIcon(self.password_show_pixmap)
        self.password_hide_icon = QIcon(self.password_hide_pixmap)
        self.password_change_button.setIcon(self.password_hide_icon)
        self.password_change_button.setStyleSheet("border:none;")
        self.password_change_button.clicked.connect(self.password_icon_change)

        self.margins = self.password_text.textMargins()
        self.password_text.setTextMargins(self.margins.left(), self.margins.top(),
                                          self.password_change_button.width(), self.margins.bottom())
        self.password_text.setPlaceholderText("请输入密码")
        self.password_layout = QHBoxLayout()
        self.password_layout.addStretch(1)
        self.password_layout.addWidget(self.password_change_button)
        self.password_layout.setSpacing(0)
        self.password_layout.setContentsMargins(0, 0, 0, 0)
        self.password_text.setLayout(self.password_layout)

        self.password_label = QLabel()
        self.password_label.setText("密码：")

        self.password_group = QWidget()
        self.password_group_layout = QHBoxLayout()
        self.password_group_layout.addWidget(self.password_label)
        self.password_group_layout.addWidget(self.password_text)
        self.password_group.setLayout(self.password_group_layout)

        self.vbox.addWidget(self.password_group)

        self.login_button_widget = QWidget()
        self.login_layout = QHBoxLayout()
        self.login_layout.addStretch(1)
        self.login_button = QPushButton()
        self.login_button.setText("登录")
        self.login_button.setFixedWidth(60)
        self.logout_button = QPushButton()
        self.logout_button.setText("下线")
        self.logout_button.setFixedWidth(60)
        self.login_layout.addWidget(self.login_button)
        self.login_layout.addWidget(self.logout_button)
        self.login_layout.addStretch(1)
        self.login_button_widget.setLayout(self.login_layout)
        self.vbox.addWidget(self.login_button_widget)

        self.keep_login_widget = QWidget()
        self.keep_login_layout = QHBoxLayout()
        self.keep_login_layout.addStretch(1)
        self.keep_login_checkBox = QCheckBox()
        self.keep_login_checkBox.setText("保持连接")
        self.keep_login_layout.addWidget(self.keep_login_checkBox)
        self.keep_login_layout.addStretch(1)
        self.keep_login_widget.setLayout(self.keep_login_layout)
        self.vbox.addWidget(self.keep_login_widget)

        self.remember_widget = QWidget()
        self.remember_layout = QHBoxLayout()
        self.remember_layout.addStretch(1)
        self.remember_checkBox = QCheckBox()
        self.remember_checkBox.setText("记住密码")
        self.remember_layout.addWidget(self.remember_checkBox)
        self.remember_layout.addStretch(1)
        self.remember_widget.setLayout(self.remember_layout)
        self.vbox.addWidget(self.remember_widget)
        self.vbox.addStretch(1)

        self.login_widget = QWidget()
        self.hbox = QHBoxLayout()
        self.hbox.addStretch(1)
        self.login_widget.setLayout(self.vbox)
        self.hbox.addWidget(self.login_widget)
        self.hbox.addStretch(1)

        self.hbox.setStretch(0, 1)
        self.hbox.setStretch(1, 8)
        self.hbox.setStretch(2, 1)

        self.main_widget = QWidget()
        self.main_widget.setLayout(self.hbox)
        self.setCentralWidget(self.main_widget)

        self.status = self.statusBar()
        self.tray.showMessage('网络连接', '初始化网络侦测中', QSystemTrayIcon.MessageIcon.Information)
        self.network_status_label = QLabel('网络连接：初始化网络侦测中 ')
        self.network_state = False
        self.status.addPermanentWidget(self.network_status_label)

        self.settings = QSettings(r"config/config.ini", QSettings.Format.IniFormat)
        self.init_config()
        self.username_combobox.currentTextChanged.connect(self.username_combobox_changed)

    def password_icon_change(self):
        self.password_show_flag = not self.password_show_flag
        if self.password_show_flag:
            self.password_text.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_change_button.setIcon(self.password_show_icon)
        else:
            self.password_text.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_change_button.setIcon(self.password_hide_icon)

    def show_message(self, flag):
        self.network_state = flag
        if self.keep_login_flag:
            if not flag:
                self.network_out_flag += 1
                if self.network_out_flag > 5:
                    self.network_out_flag = 0
                    self.login()
            else:
                self.network_out_flag = 0
        if self.first_network_detect:
            self.tray.showMessage('网络连接', f'{flag}', QSystemTrayIcon.MessageIcon.Information)
            self.first_network_detect = False
        self.network_status_label.setText(f'网络连接：{flag} ')

    def re_exit(self):
        self.tray = None
        sys.exit(app.exec())

    def re_show(self):
        self.show()

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def username_combobox_changed(self):
        try:
            index = self.username.index(self.username_combobox.lineEdit().text())
            self.password_text.setText(self.password[index])
        except:
            self.password_text.clear()

    def icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            if self.isHidden():
                self.show()
            else:
                self.hide()
        elif reason == QSystemTrayIcon.ActivationReason.Trigger:
            pass

    def init_config(self):
        username_temp = self.settings.value("account/username")
        password_temp = self.settings.value("account/password")
        userindex_temp = self.settings.value("account/userIndex")
        remember_temp = self.settings.value("remember_state/remember")
        if remember_temp:
            self.remember = True
            self.remember_checkBox.setChecked(True)
        if username_temp is not None and password_temp is not None and userindex_temp is not None:
            self.username = username_temp
            self.password = password_temp
            self.userindex = userindex_temp
            self.username_combobox.addItems(self.username)
            self.password_text.setText(self.password[0])
        del remember_temp
        del username_temp
        del userindex_temp
        del password_temp

    def login(self):
        username = self.username_combobox.lineEdit().text()
        password = self.password_text.text()
        state, user_index = login(username, password)
        if state == Login_State.login_Successful:
            if self.remember_checkBox.isChecked():
                if username not in self.username:
                    self.username.insert(0, username)
                    self.password.insert(0, password)
                    self.userindex.insert(0, user_index)
                else:
                    index = self.username.index(username)
                    if self.userindex[index] != user_index:
                        QMessageBox.information(self, "校园网", "userIndex 已更新", QMessageBox.StandardButton.Ok)
                        self.userindex[index] = user_index
                    if self.password[index] != password:
                        message = QMessageBox()
                        message.setText('校园网')
                        message.setInformativeText(f'输入的密码与存储的账户{username}密码不同，是否需要更新!')
                        message.setStandardButtons(QMessageBox.StandardButton.Save |
                                                   QMessageBox.StandardButton.Discard |
                                                   QMessageBox.StandardButton.Cancel)
                        message.setDefaultButton(QMessageBox.StandardButton.Save)
                        if message.exec() == QMessageBox.StandardButton.Save:
                            self.password[index] = password
                    password = self.password[index]
                    del self.username[index]
                    del self.password[index]
                    del self.userindex[index]
                    self.username.insert(0, username)
                    self.password.insert(0, password)
                    self.userindex.insert(0, user_index)

                self.settings.beginGroup("account")
                self.settings.setValue("username", self.username)
                self.settings.setValue("password", self.password)
                self.settings.setValue("userIndex", self.userindex)
                self.settings.endGroup()
                self.settings.beginGroup("remember_state")
                self.settings.setValue("remember", self.remember_checkBox.isChecked())
                self.settings.endGroup()
                self.settings.sync()
            self.tray.showMessage('校园网', '登录成功，Enjoy!', QSystemTrayIcon.MessageIcon.Information)
            QMessageBox.information(self, "校园网", "登录成功，Enjoy!", QMessageBox.StandardButton.Ok)
        else:
            if self.keep_login_flag:
                self.keep_login_checkBox.setChecked(False)
            if state == Login_State.username_password_NOT_SET:
                QMessageBox.critical(self, "校园网", "请填写账户名或密码", QMessageBox.StandardButton.Ok)
            elif state == Login_State.queryString_NOT_FOUND:
                if self.network_state:
                    QMessageBox.information(self, "校园网", "已登录校园网，无需重复登录", QMessageBox.StandardButton.Ok)
                else:
                    QMessageBox.information(self, "校园网", "连接失败，请检查网线/wifi是否正常连接，并检查接入网络为校园网",
                                            QMessageBox.StandardButton.Ok)
            elif state == Login_State.cookie_NOT_GET:
                QMessageBox.critical(self, "校园网", "请确保接入网络为校园网", QMessageBox.StandardButton.Ok)
            elif state == Login_State.post_data_NOT_SEND:
                QMessageBox.critical(self, "校园网", "登录请求无法发送", QMessageBox.StandardButton.Ok)
            elif state == Login_State.login_Wrong_Unknown:
                QMessageBox.critical(self, "校园网", "账户名或密码错误", QMessageBox.StandardButton.Ok)
            else:
                QMessageBox.critical(self, "校园网", "未知错误", QMessageBox.StandardButton.Ok)

    def logout(self):
        username = self.username_combobox.lineEdit().text()
        password = self.password_text.text()
        try:
            user_index = self.userindex[self.username.index(username)]
        except Exception as e:
            logging.warning(e)
            QMessageBox.information(self, "校园网", "没有当前账户的userIndex，请先登录", QMessageBox.StandardButton.Ok)
            return
        state = logout(username, password, user_index)
        if state == Logout_State.logout_Successful:
            self.tray.showMessage('校园网', '下线成功，Enjoy!', QSystemTrayIcon.MessageIcon.Information)
            QMessageBox.information(self, "校园网", "下线成功，Enjoy!", QMessageBox.StandardButton.Ok)
        elif state == Logout_State.userIndex_Wrong:
            QMessageBox.critical(self, "校园网", "userIndex 错误", QMessageBox.StandardButton.Ok)
        else:
            QMessageBox.critical(self, "校园网", "未知错误", QMessageBox.StandardButton.Ok)

    def keep_login(self):
        if self.keep_login_checkBox.checkState() == Qt.CheckState.Checked:
            self.keep_login_flag = True
        else:
            self.keep_login_flag = False


if __name__ == "__main__":
    app = QApplication(sys.argv)
    QCoreApplication.setOrganizationName("RainYQ")
    QCoreApplication.setOrganizationDomain("https://github.com/RainYQ/")
    QCoreApplication.setApplicationName("Campus Network Autologin")
    mainwindow = MainWindow()
    thread = NetworkTest()
    thread.network_flag.connect(mainwindow.show_message)
    mainwindow.login_button.clicked.connect(mainwindow.login)
    mainwindow.logout_button.clicked.connect(mainwindow.logout)
    mainwindow.keep_login_checkBox.toggled.connect(mainwindow.keep_login)
    thread.start()
    mainwindow.show()
    sys.exit(app.exec())