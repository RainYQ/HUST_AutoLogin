#HUST Campus Network AutoLogin
## Structure
```angular2html
├── root
│   ├── autosender.py // Qt MainWindow
│   ├── network_operations.py // login & logout
│   ├── headers.py  // headers for login & logout
│   ├── auto_start.py  // autostart for different system
│   ├── config/
│   │   ├── config.ini
│   ├── icons/
│   │   ├── app.svg
│   │   ├── arjv1-a2cbo-001.ico
│   │   ├── ...
│   │   └──
```
## Login
- get `queryString` from `http://123.123.123.123`
- post `data` to `http://192.168.50.3:8080/eportal/InterFace.do?method=login`
## Logout
- get `userIndex` from `http://192.168.50.3:8080//eportal/gologout.jsp` or `config`
- post `data` to `http://192.168.50.3:8080/eportal/InterFace.do?method=logout`
## Network Station
- `ping 202.114.0.131` 仅在 `Windows` 和 `Ubuntu` 测试
- fail counts > 5 ` -> login()`
## Qt MainWindow
- `保持连接` 勾选后 `ping` 检测到断网后自动 ` -> login()`
- `记住账户` 勾选后在每次 `login` or `logout` 成功后更新 `config`
- `静默模式` 勾选后与登录相关的通知被屏蔽，只能从日志中查看，配合`保持连接` 使用
- `开机自启` 勾选后开机自启动，仅在 `windows 10` or `windows 11` or `Ubuntu 20.04` or ` Ubuntu 21.04` 测试过，配合 `保持连接` 使用
## Package
```python 
pyinstaller -F -w -i ../icons/arjv1-a2cbo-004.ico ../autosender.py
```
