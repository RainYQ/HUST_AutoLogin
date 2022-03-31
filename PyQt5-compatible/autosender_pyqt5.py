import logging
import sys
import os

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S %p"
abs_path = os.path.abspath(sys.argv[0])
abs_path_dir, abs_path_filename = os.path.split(abs_path)
abs_log_path = os.path.join(abs_path_dir, 'run.log')
logging.basicConfig(filename=abs_log_path, level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)

from network_operations_pyqt5 import *
from auto_start_pyqt5 import *

from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtCore import Qt, QSettings, QCoreApplication, QVariant, QDir
from PyQt5.QtGui import QPixmap, QColor, QIcon, QPainter
from PyQt5.QtWidgets import QApplication, QAction, QLabel, QLineEdit, QHBoxLayout, QMainWindow, QWidget, QVBoxLayout, \
    QPushButton, QSystemTrayIcon, QMenu, QMessageBox, QCheckBox, QComboBox

os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(os.path.dirname(sys.argv[0]), 'cacert.pem')

QDir.addSearchPath('icons', os.path.join(abs_path_dir, "icons"))
QDir.addSearchPath('configs', os.path.join(abs_path_dir, "config"))


class MainWindow(QMainWindow):
    network_card_signal = pyqtSignal(str)

    def __init__(self):
        super(MainWindow, self).__init__()

        self.netcard_info = {}
        self.update_network()
        self.network_out_flag = 0
        self.remember = False
        self.username = []
        self.password = []
        self.userindex = []

        self.first_network_detect = True
        self.keep_login_flag = False
        self.silent_flag = False
        self.password_show_flag = False
        self.silent_message_information = True
        self.office_flag = False

        self.setWindowTitle("AutoLogin")
        self.setFixedSize(300, 500)

        self.app_svg = QSvgRenderer("icons:app.svg")
        self.app_pixmap = QPixmap(128, 128)
        self.app_pixmap.fill(QColor(0, 0, 0, 0))
        self.app_painter = QPainter(self.app_pixmap)
        self.app_svg.render(self.app_painter)
        self.app_icon = QIcon(self.app_pixmap)
        self.setWindowIcon(self.app_icon)

        self.statusBar().setSizeGripEnabled(False)
        self.setWindowFlags(Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)

        self.tray = QSystemTrayIcon()
        self.tray_svg = QSvgRenderer("icons:网络.svg")
        self.tray_pixmap = QPixmap(128, 128)
        self.tray_pixmap.fill(QColor(0, 0, 0, 0))
        self.tray_painter = QPainter(self.tray_pixmap)
        self.tray_svg.render(self.tray_painter)
        self.tray_icon = QIcon(self.tray_pixmap)
        self.tray.setIcon(self.tray_icon)

        self.show_svg = QSvgRenderer("icons:显示.svg")
        self.show_pixmap = QPixmap(128, 128)
        self.show_pixmap.fill(QColor(0, 0, 0, 0))
        self.show_painter = QPainter(self.show_pixmap)
        self.show_svg.render(self.show_painter)
        self.show_action = QAction(QIcon(self.show_pixmap), "&Show", self, triggered=self.re_show)
        self.exit_svg = QSvgRenderer("icons:退出.svg")
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
        self.password_show_svg = QSvgRenderer("icons:解锁.svg")
        self.password_show_pixmap = QPixmap(32, 32)
        self.password_show_pixmap.fill(QColor(0, 0, 0, 0))
        self.password_show_painter = QPainter(self.password_show_pixmap)
        self.password_show_svg.render(self.password_show_painter)
        self.password_hide_svg = QSvgRenderer("icons:锁定.svg")
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

        self.network_card_widget = QWidget()
        self.network_card_label = QLabel()
        self.network_card_label.setText("网卡名称：")
        self.network_card_text = QLineEdit()
        self.network_card_text.setPlaceholderText("请输入网卡名称")
        self.network_card_layout = QHBoxLayout()
        self.network_card_layout.addStretch(1)
        self.network_card_layout.addWidget(self.network_card_label)
        self.network_card_layout.addWidget(self.network_card_text)
        self.network_card_layout.addStretch(1)
        self.network_card_widget.setLayout(self.network_card_layout)
        self.vbox.addWidget(self.network_card_widget)

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
        self.remember_checkBox.setText("记住账户")
        self.remember_layout.addWidget(self.remember_checkBox)
        self.remember_layout.addStretch(1)
        self.remember_widget.setLayout(self.remember_layout)
        self.vbox.addWidget(self.remember_widget)

        self.silent_widget = QWidget()
        self.silent_layout = QHBoxLayout()
        self.silent_layout.addStretch(1)
        self.silent_checkBox = QCheckBox()
        self.silent_checkBox.setText("静默模式")
        self.silent_layout.addWidget(self.silent_checkBox)
        self.silent_layout.addStretch(1)
        self.silent_widget.setLayout(self.silent_layout)
        self.vbox.addWidget(self.silent_widget)

        self.autostart_widget = QWidget()
        self.autostart_layout = QHBoxLayout()
        self.autostart_layout.addStretch(1)
        self.autostart_checkBox = QCheckBox()
        self.autostart_checkBox.setText("开机自启")
        self.autostart_layout.addWidget(self.autostart_checkBox)
        self.autostart_layout.addStretch(1)
        self.autostart_widget.setLayout(self.autostart_layout)
        self.vbox.addWidget(self.autostart_widget)

        self.office_widget = QWidget()
        self.office_layout = QHBoxLayout()
        self.office_layout.addStretch(1)
        self.office_checkBox = QCheckBox()
        self.office_checkBox.setText("办公组")
        self.office_layout.addWidget(self.office_checkBox)
        self.office_layout.addStretch(1)
        self.office_widget.setLayout(self.office_layout)
        self.vbox.addWidget(self.office_widget)
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
        self.network_status_label = QLabel('网络连接：初始化网络侦测中 ')
        self.network_state = False
        self.status.addPermanentWidget(self.network_status_label)

        self.settings = QSettings(os.path.join(abs_path_dir, "config", "config.ini"), QSettings.Format.IniFormat)
        self.init_config()
        self.username_combobox.currentTextChanged.connect(self.username_combobox_changed)
        self.network_card_text.returnPressed.connect(self.network_card_name_change)

    def update_network(self):
        info = psutil.net_if_addrs()
        for k, v in info.items():
            mac_addr = None
            ip_addr = None
            for item in v:
                if item.family == psutil.AF_LINK:
                    mac_addr = item.address
                if item.family == socket.AddressFamily.AF_INET and not item.address == '127.0.0.1':
                    ip_addr = item.address
            if mac_addr is not None and ip_addr is not None:
                self.netcard_info[k] = [mac_addr, ip_addr]

    def network_card_name_change(self):
        self.network_card_signal.emit(self.network_card_text.text())

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
                # 连续 5 次 ping 不通认为已经断网
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
        network_card_name_temp = self.settings.value("network_card_name/netcardname")
        keeplogin_temp = self.settings.value("keeplogin_state/keeplogin")
        remember_temp = self.settings.value("remember_state/remember")
        silent_temp = self.settings.value("silent_state/silent")
        autostart_temp = self.settings.value("autostart_state/autostart")
        office_temp = self.settings.value("office_state/office")
        if network_card_name_temp:
            self.network_card_text.setText(network_card_name_temp)
        if keeplogin_temp:
            self.keep_login_flag = True
            self.keep_login_checkBox.setChecked(True)
        if remember_temp:
            self.remember = True
            self.remember_checkBox.setChecked(True)
        if silent_temp:
            self.silent_flag = True
            self.silent_checkBox.setChecked(True)
        if autostart_temp:
            self.autostart_checkBox.setChecked(True)
        if username_temp is not None and password_temp is not None and userindex_temp is not None:
            self.username = username_temp
            self.password = password_temp
            self.userindex = userindex_temp
            self.username_combobox.addItems(self.username)
            self.password_text.setText(self.password[0])
        if office_temp:
            self.office_checkBox.setChecked(True)
        del username_temp
        del userindex_temp
        del password_temp
        del network_card_name_temp
        del keeplogin_temp
        del remember_temp
        del silent_temp
        del autostart_temp
        del office_temp

    def login(self):
        username = self.username_combobox.lineEdit().text()
        password = self.password_text.text()
        network_card_name = self.network_card_text.text()
        self.update_network()
        if network_card_name == '':
            logging.warning("[-] Not set network card name. Use default network card.")
        state, user_index = login(username, password, self.netcard_info.get(network_card_name), self.office_flag)
        if state == Login_State.login_Successful:
            self.update_config(username, password, user_index)
            if not self.silent_flag:
                self.tray.showMessage('校园网', '登录成功，Enjoy!', QSystemTrayIcon.MessageIcon.Information)
        else:
            if not self.silent_flag:
                if state == Login_State.username_password_NOT_SET:
                    self.tray.showMessage('校园网', '登录失败，请填写账户名或密码', QSystemTrayIcon.MessageIcon.Warning)
                elif state == Login_State.queryString_NOT_FOUND:
                    if self.network_state:
                        self.tray.showMessage('校园网', '登录失败，已登录校园网，无需重复登录',
                                              QSystemTrayIcon.MessageIcon.Warning)
                    else:
                        self.tray.showMessage('校园网', '登录失败，请检查网线/wifi是否正常连接，并检查接入网络为校园网',
                                              QSystemTrayIcon.MessageIcon.Warning)
                elif state == Login_State.cookie_NOT_GET:
                    self.tray.showMessage('校园网', '登录失败，请确保接入网络为校园网',
                                          QSystemTrayIcon.MessageIcon.Warning)
                elif state == Login_State.post_data_NOT_SEND:
                    self.tray.showMessage('校园网', '登录失败，登录请求无法发送', QSystemTrayIcon.MessageIcon.Critical)
                elif state == Login_State.login_Wrong_Unknown:
                    self.tray.showMessage('校园网', '登录失败，账户名或密码错误', QSystemTrayIcon.MessageIcon.Critical)
                else:
                    self.tray.showMessage('校园网', '登录失败，未知错误', QSystemTrayIcon.MessageIcon.Critical)

    def update_config(self, username, password, user_index):
        if self.remember_checkBox.isChecked():
            if username not in self.username:
                self.username.insert(0, username)
                self.password.insert(0, password)
                self.userindex.insert(0, user_index)
            else:
                index = self.username.index(username)
                if self.userindex[index] != user_index:
                    self.tray.showMessage("校园网", "userIndex 已更新", QSystemTrayIcon.MessageIcon.Information)
                    logging.info(f"Account {username}: userIndex from {self.userindex[index]} to {user_index}.")
                    self.userindex[index] = user_index
                if self.password[index] != password:
                    self.tray.showMessage("校园网", "password 已更新", QSystemTrayIcon.MessageIcon.Information)
                    logging.info(f"Account {username}: password update.")
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
            self.settings.beginGroup("network_card_name")
            self.settings.setValue("netcardname", self.network_card_text.text())
            self.settings.endGroup()
            self.settings.beginGroup("keeplogin_state")
            self.settings.setValue("keeplogin", self.keep_login_checkBox.isChecked())
            self.settings.endGroup()
            self.settings.beginGroup("remember_state")
            self.settings.setValue("remember", self.remember_checkBox.isChecked())
            self.settings.endGroup()
            self.settings.beginGroup("silent_state")
            self.settings.setValue("silent", self.silent_checkBox.isChecked())
            self.settings.endGroup()
            self.settings.beginGroup("autostart_state")
            self.settings.setValue("autostart", self.autostart_checkBox.isChecked())
            self.settings.endGroup()
            self.settings.beginGroup("office_state")
            self.settings.setValue("office", self.autostart_checkBox.isChecked())
            self.settings.endGroup()
            self.settings.sync()

    def logout(self):
        username = self.username_combobox.lineEdit().text()
        password = self.password_text.text()
        network_card_name = self.network_card_text.text()
        try:
            user_index = None
            try:
                self.update_network()
                if network_card_name == '':
                    logging.warning("[-] Not set network card name. Use default network card.")
                user_index = get_index(username, password, self.netcard_info.get(network_card_name), self.office_flag)
            except Exception as e:
                logging.error(e)
            if user_index is None:
                user_index = self.userindex[self.username.index(username)]
        except Exception as e:
            logging.error(e)
            QMessageBox.information(self, "校园网", "没有当前账户的userIndex，请断网重新登录", QMessageBox.StandardButton.Ok)
            return
        self.update_network()
        if network_card_name == '':
            logging.warning("[-] Not set network card name. Use default network card.")
        state = logout(username, password, user_index, self.netcard_info.get(network_card_name), self.office_flag)
        if state == Logout_State.logout_Successful:
            self.update_config(username, password, user_index)
            self.tray.showMessage('校园网', '下线成功，Enjoy!', QSystemTrayIcon.MessageIcon.Information)
        elif state == Logout_State.userIndex_Wrong:
            self.tray.showMessage('校园网', '下线失败，userIndex 错误', QSystemTrayIcon.MessageIcon.Information)
        else:
            self.tray.showMessage('校园网', '下线失败，未知错误', QSystemTrayIcon.MessageIcon.Information)

    def keep_login(self):
        if self.keep_login_checkBox.checkState() == Qt.CheckState.Checked:
            self.keep_login_flag = True
        else:
            self.keep_login_flag = False

    def office_check(self):
        if self.office_checkBox.checkState() == Qt.CheckState.Checked:
            self.office_flag = True
        else:
            self.office_flag = False

    def silent(self):
        if self.silent_checkBox.checkState() == Qt.CheckState.Checked:
            self.silent_flag = True
            if self.silent_message_information:
                logging.info("Silent Mode Start.")
                QMessageBox.warning(self, "校园网",
                                    "启用静默模式后，所有与登录相关的information/warning/error均无弹窗提示，请在日志中查看登录状态",
                                    QMessageBox.StandardButton.Ok)
                self.silent_message_information = False
        else:
            self.silent_flag = False
            self.silent_message_information = True

    def autostart(self):
        if platform.system() == "Windows":
            if self.autostart_checkBox.checkState() == Qt.CheckState.Checked:
                autorun_windows(abspath=os.path.abspath(sys.argv[0]), switch='open', key_name=autostart_key_name)
            else:
                autorun_windows(abspath=os.path.abspath(sys.argv[0]), switch='close', key_name=autostart_key_name)
        elif platform.system() == "Linux":
            if self.autostart_checkBox.checkState() == Qt.CheckState.Checked:
                autorun_linux(abs_path_dir=abs_path_dir, abspath=os.path.abspath(sys.argv[0]), switch='open')
            else:
                autorun_linux(abs_path_dir=abs_path_dir, abspath=os.path.abspath(sys.argv[0]), switch='close')
        else:
            logging.error("[-] Not Supported System type.")
            self.tray.showMessage('校园网', '非 Windows / Linux 系统，开机自启模块无法启动',
                                  QSystemTrayIcon.MessageIcon.Critical)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    QCoreApplication.setOrganizationName("RainYQ")
    QCoreApplication.setOrganizationDomain("https://github.com/RainYQ/")
    QCoreApplication.setApplicationName("Campus Network Autologin")
    mainwindow = MainWindow()
    thread = NetworkTest(mainwindow.netcard_info)
    thread.network_flag.connect(mainwindow.show_message)
    mainwindow.network_card_signal.connect(thread.setcardname)
    mainwindow.login_button.clicked.connect(mainwindow.login)
    mainwindow.logout_button.clicked.connect(mainwindow.logout)
    mainwindow.keep_login_checkBox.toggled.connect(mainwindow.keep_login)
    mainwindow.silent_checkBox.toggled.connect(mainwindow.silent)
    mainwindow.autostart_checkBox.toggled.connect(mainwindow.autostart)
    thread.start()
    try:
        if platform.system() == "Windows":
            key_exit = judge_key(reg_root=win32con.HKEY_CURRENT_USER,
                                 reg_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 key_name=autostart_key_name,
                                 abspath=os.path.abspath(sys.argv[0]))
            if key_exit == 0 or key_exit == 1:
                mainwindow.autostart_checkBox.setChecked(True)
        elif platform.system() == "Linux":
            if os.path.exists(f"{os.environ['HOME']}/.config/autostart/{autostart_key_name}.desktop"):
                mainwindow.autostart_checkBox.setChecked(True)
    except Exception as e:
        logging.error(e)
    mainwindow.show()
    sys.exit(app.exec())
