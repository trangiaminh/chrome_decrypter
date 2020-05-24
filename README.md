# Chrome Decrypter
Chrome Decrypter (Passwords & Cookies)

## Python v3
- Windows x86: https://www.python.org/ftp/python/3.8.3/python-3.8.3.exe | https://www.python.org/ftp/python/3.8.3/python-3.8.3-embed-win32.zip
- Windows x64: https://www.python.org/ftp/python/3.8.3/python-3.8.3-amd64.exe | https://www.python.org/ftp/python/3.8.3/python-3.8.3-embed-amd64.zip
- Install pip for python embedded distribution on windows: https://www.christhoung.com/2018/07/15/embedded-python-windows/

## How to run
1. Install virtual env python: `.\install_env.bat`
2. In activated cmd window, install dependencies: `pip install -r .\requirements.txt`
3. In activated cmd window, decrypt passwords & cookies in Chrome: `python .\chrome_decrypter.py`

## Result:
- **Password files**: passwords.txt & passwords.json
- **Cookie files**: cookies.txt & cookies.json
