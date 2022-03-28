import logging
import os
import platform
import sys

try:
    import win32api
    import win32con, winreg
except Exception as e:
    logging.error(e)
    pass

autostart_key_name = 'hust_campus_network_autologin'
abs_path = os.path.abspath(sys.argv[0])
abs_path_dir, abs_path_filename = os.path.split(abs_path)

if platform.system() == "Windows":
    def judge_key(key_name=None,
                  reg_root=win32con.HKEY_CURRENT_USER,
                  reg_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                  abspath=None
                  ):
        reg_flags = win32con.WRITE_OWNER | win32con.KEY_WOW64_64KEY | win32con.KEY_ALL_ACCESS
        try:
            key = winreg.OpenKey(reg_root, reg_path, 0, reg_flags)
            location, type = winreg.QueryValueEx(key, key_name)
            logging.info(f"location: {location}, type: {type}.")
            feedback = 0
            if location != abspath:
                feedback = 1
                logging.info(f'Current location: {abspath}, App Location Changed.')
        except FileNotFoundError as e:
            logging.error(e)
            feedback = 2
        except PermissionError as e:
            logging.error(e)
            feedback = 3
        except Exception as e:
            logging.error(e)
            feedback = 4
        return feedback


    def autorun_windows(switch="open",
                        key_name=None,
                        abspath=os.path.abspath(sys.argv[0])):
        key_exit = judge_key(reg_root=win32con.HKEY_CURRENT_USER,
                             reg_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
                             key_name=key_name,
                             abspath=abspath)
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, reg_path, 0, win32con.KEY_ALL_ACCESS)
        if switch == "open":
            try:
                if key_exit == 0:
                    logging.info('[+] Auto Start has been set successfully. No need setting again.')
                elif key_exit == 1 or key_exit == 2:
                    win32api.RegSetValueEx(key, key_name, 0, win32con.REG_SZ, abspath)
                    win32api.RegCloseKey(key)
                    if key_exit == 1:
                        logging.info('[+] Auto Start key update successful.')
                    else:
                        logging.info('[+] Auto Start key create successful.')
                elif key_exit == 3:
                    logging.error('[-] No Suitable Permission.')
            except Exception as e:
                logging.error(e)
                logging.error('[-] Unknown Error. Cannot Auto Start.')
        elif switch == "close":
            try:
                if key_exit == 0 or key_exit == 1:
                    win32api.RegDeleteValue(key, key_name)
                    win32api.RegCloseKey(key)
                    if key_exit == 0:
                        logging.info('[+] Auto Start key delete successful.')
                    else:
                        logging.info('[+] Auto Start key location wrong.')
                elif key_exit == 2:
                    logging.info('[+] Auto Start key does not exist.')
                elif key_exit == 3:
                    logging.error('[-] No Suitable Permission.')
                else:
                    logging.error('[-] Unknown Error. Cannot delete Auto Start key.')
            except Exception as e:
                logging.error(e)
                logging.error('[-] Unknown Error. Cannot delete Auto Start key.')
elif platform.system() == "Linux":
    def autorun_linux(switch="open"):
        if switch == "open":
            desktop_content = "[Desktop Entry]\n"
            desktop_content += f"Icon={abs_path_dir}/icons/arjv1-a2cbo-004.ico\n"
            desktop_content += f"Exec={abs_path_dir}/autosender\n"
            desktop_content += "Version=beta-0.3.0\n"
            desktop_content += "Type=Application\n"
            desktop_content += "Categories=Development\n"
            desktop_content += "Name=HUST AutoLogin\n"
            desktop_content += "StartupWMClass=HUST AutoLogin\n"
            desktop_content += "Terminal=false\n"
            desktop_content += "MimeType=x-scheme-handler/rainyq;\n"
            desktop_content += "X-GNOME-Autostart-enabled=true\n"
            desktop_content += "StartupNotify=false\n"
            desktop_content += "X-GNOME-Autostart-Delay=10\n"
            desktop_content += "X-MATE-Autostart-Delay=10\n"
            desktop_content += "X-KDE-autostart-after=panel\n"
            os.system(f"echo '{desktop_content}' > ~/.config/autostart/{autostart_key_name}.desktop")
        elif switch == "close":
            os.system(f"rm -rf ~/.config/autostart/{autostart_key_name}.desktop")