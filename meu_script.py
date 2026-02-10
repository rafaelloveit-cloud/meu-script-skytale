import requests
import os
import sys
import tempfile
import subprocess
import time
from datetime import datetime

# ================== CONFIGURAÇÕES ==================
GITHUB_USER = "rafaelloveit-cloud"
GITHUB_REPO = "meu-script-skytale"

# Para .py (modo desenvolvimento)
VERSION_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/version.txt"
SCRIPT_URL  = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/meu_script.py"

# Para .exe (recomendado para distribuição)
RELEASES_API = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"

CURRENT_VERSION = "1.0.1"          # Mantenha sincronizado
EXE_NAME = "OperaOpera Internet Browser.exe"             # ← Nome do seu .exe compilado (mude se for diferente)

# ===================================================

def is_frozen():
    """Retorna True se estiver rodando como .exe compilado"""
    return getattr(sys, 'frozen', False)

def verificar_atualizacao():
    """Verifica e atualiza automaticamente (funciona em .py e .exe)"""
    print("🔍 Verificando atualizações...")

    try:
        if not is_frozen():
            # ================== MODO .PY ==================
            versao_remota = requests.get(VERSION_URL, timeout=10).text.strip()
            
            if versao_remota <= CURRENT_VERSION:
                print(f"✅ Você já está na versão mais recente ({CURRENT_VERSION})")
                return False

            print(f"🔥 Nova versão disponível: {versao_remota}")
            
            resposta = requests.get(SCRIPT_URL, timeout=15)
            resposta.raise_for_status()

            with tempfile.NamedTemporaryFile(delete=False, suffix='.py', mode='w', encoding='utf-8') as tmp:
                tmp.write(resposta.text)
                novo_arquivo = tmp.name

            script_atual = sys.argv[0]
            backup = script_atual + ".old"
            
            if os.path.exists(backup):
                os.remove(backup)
            os.rename(script_atual, backup)
            os.rename(novo_arquivo, script_atual)

            print("✅ Script atualizado! Reiniciando...")
            os.execv(sys.executable, [sys.executable] + sys.argv)

        else:
            # ================== MODO .EXE ==================
            r = requests.get(RELEASES_API, timeout=10)
            r.raise_for_status()
            release = r.json()

            tag = release["tag_name"].lstrip("v")
            if tag <= CURRENT_VERSION:
                print(f"✅ Você já está na versão mais recente ({CURRENT_VERSION})")
                return False

            print(f"🔥 Nova versão disponível: {tag}")

            # Procura o asset com o nome do exe
            asset = next((a for a in release["assets"] if a["name"].lower() == EXE_NAME.lower()), None)
            if not asset:
                print("❌ Asset do .exe não encontrado na release!")
                return False

            download_url = asset["browser_download_url"]
            
            # Baixa nova versão
            resposta = requests.get(download_url, timeout=30)
            resposta.raise_for_status()

            exe_path = sys.executable
            new_exe = os.path.join(os.path.dirname(exe_path), f"{EXE_NAME}_new")
            updater_bat = os.path.join(os.path.dirname(exe_path), "updater.bat")

            with open(new_exe, "wb") as f:
                f.write(resposta.content)

            # Cria o updater.bat
            bat_content = f"""@echo off
timeout /t 2 /nobreak >nul
taskkill /f /im "{os.path.basename(exe_path)}" >nul 2>&1
del "{exe_path}" >nul 2>&1
ren "{new_exe}" "{os.path.basename(exe_path)}"
start "" "{exe_path}"
del "%~f0"
"""

            with open(updater_bat, "w", encoding="utf-8") as f:
                f.write(bat_content)

            print("✅ Atualização baixada! Aplicando...")
            subprocess.Popen([updater_bat], creationflags=subprocess.CREATE_NEW_CONSOLE)
            sys.exit(0)

    except Exception as e:
        print(f"⚠️ Erro ao verificar atualização: {e}")
        return False


# ====================== SEU CÓDIGO AQUI ======================
if __name__ == "__main__":
    verificar_atualizacao()
    
    # ... (todo o resto do seu código continua igual)
    print("="*50)
    print("🚀 Meu Script Incrível - Versão", CURRENT_VERSION)
    print("="*50)
    print("Este script se atualiza automaticamente!")
    print("Teste: mude a versão no GitHub e rode novamente.\n")
    
    # ================= VERSÃO CORRIGIDA v1.0 - SKL COM SOMA DIRETA =================
# FR: Game.exe+5537C10 ✓
# SKL: Game.exe+554DD30 + 128 -> base dos skills ✓ CORRIGIDO PARA SOMA DIRETA
# POT: Game.exe+27DF73 ✓
# ==============================================================================
import sys
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(
            ctypes.windll.kernel32.GetConsoleWindow(), 0
        )
    except:
        pass
# ================= IMPORTS =================
import json
import base64
import requests
import keyboard
import pymem
import pymem.process
import pymem.pattern
import pymem.exception
import time
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import threading
import os
import hashlib
import platform
import subprocess
import binascii
try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        if os.name == 'nt':
            os.system("pip install pywin32")
        os.system("pip install requests")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QVBoxLayout, QCheckBox, QSystemTrayIcon, QMenu,
    QHBoxLayout, QFrame, QGraphicsOpacityEffect,
    QTextEdit, QMessageBox, QGridLayout, QDialog, QLineEdit,
    QFormLayout, QKeySequenceEdit
)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty, QThread, pyqtSignal, QEvent, QPoint
from PyQt6.QtGui import QIcon, QFont, QPixmap, QPainter, QColor, QTextCursor, QKeyEvent, QMouseEvent, QKeySequence
from qt_material import apply_stylesheet

class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Windows":
            try:
                sid = win32security.GetFileSecurity('.', win32security.OWNER_SECURITY_INFORMATION).GetSecurityDescriptorOwner()
                return win32security.ConvertSidToStringSid(sid)
            except:
                return subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        elif platform.system() == "Linux":
            return subprocess.check_output('hal-get-property --udi /org/freedesktop/Hal/devices/computer --key system.hardware.uuid'.split()).decode().strip()
        elif platform.system() == "Darwin":
            return subprocess.check_output('ioreg -l | grep IOPlatformSerialNumber'.split()).decode().split('=')[1].strip()

def get_checksum():
    md5_hash = hashlib.md5()
    try:
        with open(sys.argv[0], "rb") as file:
            md5_hash.update(file.read())
        return md5_hash.hexdigest()
    except:
        return "unknown"

class api:

    name = ownerid = version = hash_to_check = ""

    def __init__(self, name, ownerid, version, hash_to_check):
        if len(ownerid) != 10:
            print("Visit https://keyauth.cc/app/, copy Python code, and replace code in main.py with that")
            time.sleep(3)
            os._exit(1)
    
        self.name = name
        self.ownerid = ownerid
        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):
        if self.sessionid != "":
            print("You've already initialized!")
            return
        
        post_data = {
            "type": "init",
            "ver": self.version,
            "hash": self.hash_to_check,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            time.sleep(3)
            os._exit(1)

        try:
            json_data = json.loads(response)
        except:
            print("Invalid response from KeyAuth API")
            time.sleep(3)
            os._exit(1)

        if json_data.get("message") == "invalidver":
            if json_data.get("download", "") != "":
                print("New Version Available")
                download_link = json_data["download"]
                os.system(f"start {download_link}")
                time.sleep(3)
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                time.sleep(3)
                os._exit(1)

        if not json_data.get("success", False):
            print(json_data.get("message", "Unknown error"))
            time.sleep(3)
            os._exit(1)

        self.sessionid = json_data.get("sessionid", "")
        self.initialized = True

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "register",
            "username": user,
            "pass": password,
            "key": license,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            print("Invalid response from KeyAuth API")
            time.sleep(3)
            os._exit(1)

        if json_data.get("success", False):
            print(json_data.get("message", "Registration successful"))
            self.__load_user_data(json_data.get("info", {}))
            return True
        else:
            print(json_data.get("message", "Registration failed"))
            return False

    def upgrade(self, user, license):
        self.checkinit()

        post_data = {
            "type": "upgrade",
            "username": user,
            "key": license,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            print("Invalid response from KeyAuth API")
            return False

        if json_data.get("success", False):
            print(json_data.get("message", "Upgrade successful"))
            print("Please restart program and login")
            time.sleep(3)
            os._exit(1)
        else:
            print(json_data.get("message", "Upgrade failed"))
            return False

    def login(self, user, password, code=None, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "login",
            "username": user,
            "pass": password,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid,
        }
        
        if code is not None:
            post_data["code"] = code

        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            print("Invalid response from KeyAuth API")
            return False

        if json_data.get("success", False):
            self.__load_user_data(json_data.get("info", {}))
            print(json_data.get("message", "Login successful"))
            return True
        else:
            print(json_data.get("message", "Login failed"))
            return False

    def license(self, key, code=None, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "license",
            "key": key,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        if code is not None:
            post_data["code"] = code

        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            print("Invalid response from KeyAuth API")
            return False

        if json_data.get("success", False):
            self.__load_user_data(json_data.get("info", {}))
            print(json_data.get("message", "License validated"))
            return True
        else:
            print(json_data.get("message", "License validation failed"))
            return False

    def var(self, name):
        self.checkinit()

        post_data = {
            "type": "var",
            "varid": name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            return None

        if json_data.get("success", False):
            return json_data.get("message", "")
        else:
            return None

    def getvar(self, var_name):
        self.checkinit()

        post_data = {
            "type": "getvar",
            "var": var_name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            return None

        if json_data.get("success", False):
            return json_data.get("response", "")
        else:
            print(f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables")
            return None

    def setvar(self, var_name, var_data):
        self.checkinit()

        post_data = {
            "type": "setvar",
            "var": var_name,
            "data": var_data,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            return False

        if json_data.get("success", False):
            return True
        else:
            return False

    def ban(self):
        self.checkinit()

        post_data = {
            "type": "ban",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            return False

        if json_data.get("success", False):
            return True
        else:
            return False

    def file(self, fileid):
        self.checkinit()

        post_data = {
            "type": "file",
            "fileid": fileid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            return None

        if not json_data.get("success", False):
            print(json_data.get("message", "File retrieval failed"))
            return None
        
        try:
            return binascii.unhexlify(json_data.get("contents", ""))
        except:
            return None

    def webhook(self, webid, param, body="", conttype=""):
        self.checkinit()

        post_data = {
            "type": "webhook",
            "webid": webid,
            "params": param,
            "body": body,
            "conttype": conttype,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        try:
            json_data = json.loads(response)
        except:
            return None

        if json_data.get("success", False):
            return json_data.get("message", "")
        else:
            return None

    def check(self):
        self.checkinit()

        post_data = {
            "type": "check",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)
            return json_data.get("success", False)
        except:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()

        post_data = {
            "type": "checkblacklist",
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)
            return json_data.get("success", False)
        except:
            return False

    def log(self, message):
        self.checkinit()

        post_data = {
            "type": "log",
            "pcuser": os.getenv('username'),
            "message": message,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        try:
            self.__do_request(post_data)
        except:
            pass

    def fetchOnline(self):
        self.checkinit()

        post_data = {
            "type": "fetchOnline",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)

            if json_data.get("success", False):
                if len(json_data.get("users", [])) == 0:
                    return None
                else:
                    return json_data["users"]
            else:
                return None
        except:
            return None
            
    def fetchStats(self):
        self.checkinit()

        post_data = {
            "type": "fetchStats",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)

            if json_data.get("success", False):
                self.__load_app_data(json_data.get("appinfo", {}))
                return True
        except:
            pass
        return False
            
    def chatGet(self, channel):
        self.checkinit()

        post_data = {
            "type": "chatget",
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)

            if json_data.get("success", False):
                return json_data.get("messages", [])
            else:
                return None
        except:
            return None

    def chatSend(self, message, channel):
        self.checkinit()

        post_data = {
            "type": "chatsend",
            "message": message,
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)

            if json_data.get("success", False):
                return True
            else:
                return False
        except:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(3)
            os._exit(1)

    def changeUsername(self, username):
        self.checkinit()

        post_data = {
            "type": "changeUsername",
            "newUsername": username,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)

            if json_data.get("success", False):
                print("Successfully changed username")
                return True
            else:
                print(json_data.get("message", "Failed to change username"))
                return False
        except:
            return False

    def logout(self):
        self.checkinit()

        post_data = {
            "type": "logout",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        try:
            response = self.__do_request(post_data)
            json_data = json.loads(response)

            if json_data.get("success", False):
                print("Successfully logged out")
                return True
            else:
                print(json_data.get("message", "Logout failed"))
                return False
        except:
            return False

    def __do_request(self, post_data):
        try:
            rq = requests.post(
                "https://keyauth.win/api/1.3/", data=post_data, timeout=30
            )
            if rq.status_code in [520, 521, 522]:
                print("Cloudflare is acting up, please try again later.")
                return None
            return rq.text
        except requests.exceptions.Timeout:
            print("Connection timeout! Please check your internet connection.")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Connection error: {e}")
            return None

    user_data = None

    def __load_user_data(self, data):
        if not data:
            return
        
        user_data = data_class(
            data.get("username", ""),
            data.get("ip", ""),
            data.get("hwid", ""),
            data.get("createdate", ""),
            data.get("lastlogin", ""),
            data.get("subscription", ""),
            data.get("subscriptions", [])
        )
        self.user_data = user_data

    app_data = None

    def __load_app_data(self, data):
        if not data:
            return
            
        app_data = data_class(
            data.get("numUsers", ""),
            data.get("numOnlineUsers", ""),
            data.get("numKeys", ""),
            data.get("version", ""),
            data.get("customerPanelLink", ""),
            data.get("numFiles", ""),
            None
        )
        self.app_data = app_data

class data_class:
    # user data
    username = ip = hwid = createdate = lastlogin = subscription = subscriptions = None

    # app data
    numUsers = numOnlineUsers = numKeys = version = customerPanelLink = numFiles = None

    def __init__(self, numUsers_or_username=None, numOnlineUsers_or_ip=None, numKeys_or_hwid=None, version_or_createdate=None, customerPanelLink_or_lastlogin=None, numFiles_or_subscription=None, subscriptions=None):
        self.numUsers = numUsers_or_username
        self.numOnlineUsers = numOnlineUsers_or_ip
        self.numKeys = numKeys_or_hwid
        self.version = version_or_createdate
        self.customerPanelLink = customerPanelLink_or_lastlogin
        self.numFiles = numFiles_or_subscription
        self.subscriptions = subscriptions

        self.username = numUsers_or_username
        self.ip = numOnlineUsers_or_ip
        self.hwid = numKeys_or_hwid
        self.createdate = version_or_createdate
        self.lastlogin = customerPanelLink_or_lastlogin
        self.subscription = numFiles_or_subscription
        self.subscriptions = subscriptions

# ================= LOGGING =================
handler = RotatingFileHandler(
    "opera_debug.log",
    maxBytes=5*1024*1024,
    backupCount=3,
    encoding='utf-8'
)
handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
))
logging.basicConfig(
    level=logging.DEBUG, # DEBUG mode para ver tudo
    handlers=[handler]
)
# ================= ADMIN CHECK =================
def check_admin_rights() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False
# ================= ENCRYPTION =================
_CIPHER = 0x42
def _xor_cipher(data: bytes) -> bytes:
    return bytes(b ^ _CIPHER for b in data)
def encode_string(text: str) -> str:
    return base64.b64encode(_xor_cipher(text.encode())).decode()
def decode_string(text: str) -> str:
    try:
        return _xor_cipher(base64.b64decode(text)).decode(errors="ignore")
    except:
        return ""
_MONITORED_PROCESS = encode_string("Game.exe")
# ================= ADVANCED MEMORY WRITER =================
class AdvancedMemoryWriter:
    """Classe aprimorada para escrita de memória"""
   
    def __init__(self, process_handle: pymem.Pymem, max_retries: int = 5):
        self.process = process_handle
        self.max_retries = max_retries
        self.write_delay = 0.02
        self.verification_enabled = True
        self.last_write_times = {}
        self.write_locks = {}
       
    def unprotect_memory(self, address: int, size: int = 4096) -> bool:
        """Remove proteção de memória"""
        try:
            import ctypes
            from ctypes import wintypes
           
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            old_protect = wintypes.DWORD()
           
            result = kernel32.VirtualProtectEx(
                self.process.process_handle,
                address,
                size,
                0x40, # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect)
            )
           
            if result:
                logging.debug(f"🔓 Memory unprotected @ {hex(address)}")
           
            return bool(result)
               
        except Exception as e:
            logging.error(f"❌ Unprotect error: {e}")
            return False
       
    def write_byte_safe(self, address: int, value: int, verify: bool = True) -> bool:
        """Escreve um byte com verificação"""
        if address not in self.write_locks:
            self.write_locks[address] = threading.Lock()
       
        with self.write_locks[address]:
            self.unprotect_memory(address, 1)
           
            for attempt in range(self.max_retries):
                try:
                    current_value = self.process.read_uchar(address)
                   
                    if current_value == value:
                        return True
                   
                    self.process.write_uchar(address, value)
                    time.sleep(self.write_delay)
                   
                    if verify and self.verification_enabled:
                        read_back = self.process.read_uchar(address)
                       
                        if read_back == value:
                            self.last_write_times[address] = time.time()
                            logging.info(f"✓ BYTE @ {hex(address)}: {current_value} → {value}")
                            return True
                        else:
                            if attempt < self.max_retries - 1:
                                time.sleep(self.write_delay * 2)
                                continue
                            else:
                                logging.warning(f"⚠ BYTE verify failed @ {hex(address)}")
                                return False
                    else:
                        self.last_write_times[address] = time.time()
                        return True
                       
                except Exception as e:
                    logging.error(f"❌ BYTE error @ {hex(address)}: {e}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.write_delay * 3)
                        continue
                    return False
           
            return False
   
    def write_int_safe(self, address: int, value: int, verify: bool = True) -> bool:
        """Escreve um inteiro (4 bytes)"""
        if address not in self.write_locks:
            self.write_locks[address] = threading.Lock()
       
        with self.write_locks[address]:
            self.unprotect_memory(address, 4)
           
            for attempt in range(self.max_retries):
                try:
                    current_value = self.process.read_int(address)
                   
                    if current_value == value:
                        return True
                   
                    self.process.write_int(address, value)
                    time.sleep(self.write_delay)
                   
                    if verify and self.verification_enabled:
                        read_back = self.process.read_int(address)
                       
                        if read_back == value:
                            self.last_write_times[address] = time.time()
                            logging.info(f"✓ INT @ {hex(address)}: {current_value} → {value}")
                            return True
                        else:
                            if attempt < self.max_retries - 1:
                                time.sleep(self.write_delay * 2)
                                continue
                            else:
                                logging.warning(f"⚠ INT verify failed @ {hex(address)}")
                                return False
                    else:
                        self.last_write_times[address] = time.time()
                        return True
                       
                except Exception as e:
                    logging.error(f"❌ INT error @ {hex(address)}: {e}")
                    if attempt < self.max_retries - 1:
                        time.sleep(self.write_delay * 3)
                        continue
                    return False
           
            return False
   
    def read_byte_safe(self, address: int) -> Optional[int]:
        """Lê um byte"""
        try:
            return self.process.read_uchar(address)
        except Exception as e:
            logging.error(f"Read byte error @ {hex(address)}: {e}")
            return None
   
    def read_int_safe(self, address: int) -> Optional[int]:
        """Lê um inteiro"""
        try:
            return self.process.read_int(address)
        except Exception as e:
            logging.error(f"Read int error @ {hex(address)}: {e}")
            return None
   
    def read_longlong_safe(self, address: int) -> Optional[int]:
        """Lê um long long (8 bytes) para ponteiros"""
        try:
            value = self.process.read_longlong(address)
            logging.debug(f"Read longlong @ {hex(address)}: {hex(value)}")
            return value
        except Exception as e:
            logging.error(f"Read longlong error @ {hex(address)}: {e}")
            return None
   
    def force_write_int(self, address: int, value: int, max_attempts: int = 10) -> bool:
        """Força escrita de integer"""
        self.unprotect_memory(address, 4)
       
        for i in range(max_attempts):
            if self.write_int_safe(address, value, verify=True):
                logging.info(f"✓ Force INT SUCCESS @ {hex(address)} = {value}")
                return True
            time.sleep(0.05)
       
        logging.error(f"❌ Force INT FAILED @ {hex(address)}")
        return False
   
    def force_write_byte(self, address: int, value: int, max_attempts: int = 10) -> bool:
        """Força escrita de byte"""
        self.unprotect_memory(address, 1)
       
        for i in range(max_attempts):
            if self.write_byte_safe(address, value, verify=True):
                logging.info(f"✓ Force BYTE SUCCESS @ {hex(address)} = {value}")
                return True
            time.sleep(0.05)
       
        logging.error(f"❌ Force BYTE FAILED @ {hex(address)}")
        return False
# ================= EVENT SYSTEM =================
class EventLevel(Enum):
    INFO = ("INFO", "#2196F3")
    SUCCESS = ("OK", "#00E676")
    WARNING = ("WARN", "#FFC107")
    ERROR = ("ERR", "#F44336")
    DEBUG = ("DBG", "#9C27B0")
class OperaEventLogger:
    def __init__(self, max_logs: int = 500):
        self.log_entries = []
        self.max_logs = max_logs
        self.observers = []
  
    def add_observer(self, callback):
        self.observers.append(callback)
  
    def log_event(self, level: EventLevel, message: str, component: str = "OPERA"):
        entry = {
            "time": datetime.now(),
            "level": level,
            "message": message,
            "component": component
        }
        self.log_entries.append(entry)
       
        if len(self.log_entries) > self.max_logs:
            self.log_entries = self.log_entries[-self.max_logs:]
      
        for observer in self.observers:
            try:
                observer(entry)
            except:
                pass
      
        logging.info(f"[{component}] {message}")
opera_logger = OperaEventLogger()
# ================= CONFIG =================
OPERA_CONFIG = "opera_preferences.json"
OPERA_LICENSE = "opera_license.dat"
OPERA_LICENSE_BAK = "opera_license.bak"
def load_preferences() -> dict:
    defaults = {
        "auto_sync": True,
        "force_write": True,
        "verify_writes": True,
        "hotkeys": {
            "fr": "'",
            "pot": "ctrl+;",
            "skl": "ctrl+s"
        }
    }
    try:
        with open(OPERA_CONFIG, "r", encoding="utf-8") as f:
            config = json.load(f)
            for key in defaults:
                config.setdefault(key, defaults[key])
            return config
    except:
        return defaults.copy()
def save_preferences(prefs: dict) -> bool:
    try:
        with open(OPERA_CONFIG, "w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=4)
        return True
    except:
        return False
opera_prefs = load_preferences()
# ================= ICON =================
def create_opera_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
  
    painter.setBrush(QColor(255, 27, 45))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(4, 4, 56, 56)
  
    painter.setPen(QColor(255, 255, 255))
    font = QFont("Arial", 28, QFont.Weight.Bold)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "O")
    painter.end()
    return QIcon(pixmap)
# ================= DEBUG CONSOLE =================
class DebugConsole(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background: rgba(15, 15, 15, 240);
                border: 2px solid #FF1B2D;
                border-radius: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
      
        header = QLabel("📋 Historico")
        header.setStyleSheet("color: #FF1B2D; font-size: 12px; font-weight: bold;")
        layout.addWidget(header)
      
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("""
            QTextEdit {
                background: rgba(5, 5, 5, 240);
                color: #e0e0e0;
                border: none;
                font-family: Consolas;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.console_output)
      
        opera_logger.add_observer(self.on_event)
  
    def on_event(self, entry):
        timestamp = entry["time"].strftime("%H:%M:%S")
        level_name, level_color = entry["level"].value
        msg = entry["message"]
      
        html = f'<span style="color:#666">[{timestamp}]</span> '
        html += f'<span style="color:{level_color}"><b>[{level_name}]</b></span> {msg}<br>'
      
        self.console_output.moveCursor(QTextCursor.MoveOperation.End)
        self.console_output.insertHtml(html)
        self.console_output.moveCursor(QTextCursor.MoveOperation.End)
# ================= PROCESS WATCHER =================
class ProcessWatcher(QThread):
    process_detected = pyqtSignal(object, int)
    process_lost = pyqtSignal()
  
    def __init__(self):
        super().__init__()
        self.active = True
  
    def run(self):
        while self.active:
            try:
                handle = pymem.Pymem(decode_string(_MONITORED_PROCESS))
                module = pymem.process.module_from_name(
                    handle.process_handle,
                    decode_string(_MONITORED_PROCESS)
                )
                base = module.lpBaseOfDll
              
                self.process_detected.emit(handle, base)
              
                while self.active:
                    try:
                        handle.read_bytes(base, 1)
                        time.sleep(2)
                    except:
                        break
              
                self.process_lost.emit()
              
            except pymem.exception.ProcessNotFound:
                time.sleep(2)
            except Exception as e:
                time.sleep(2)
  
    def stop_watching(self):
        self.active = False
# ================= MAIN MANAGER =================
class OperaExtensionManager(QWidget):
    toggle_visibility_signal = pyqtSignal()  # Sinal para thread safety
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Opera Internet Browser")
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
      
        self.setFixedSize(460, 550)
        self.setWindowIcon(create_opera_icon())
      
        self.mem_handle = None
        self.proc_base = None
        self.connected = False
        self.memory_writer = None
        self.is_authenticated = False  # Flag de autenticação
       
        # Endereços resolvidos
        self.fr_address = None
        self.skill_addresses = [] # Lista com os 16 endereços dos skills
       
        # POT state
        self.pot_active = False
        self.pot_addr = None
        self.pot_orig = None
       
        self.dragging = False
        self.drag_pos = QPoint()
        self.header = None
       
        self.hotkeys = opera_prefs.get('hotkeys', {
            "fr": "'",
            "pot": "ctrl+;",
            "skl": "ctrl+s"
        })
       
        self._create_ui()
      
        self.watcher = ProcessWatcher()
        self.watcher.process_detected.connect(self.on_process_found)
        self.watcher.process_lost.connect(self.on_process_lost)
        self.watcher.start()
      
        # Timers anti-revert
        self.fr_timer = QTimer()
        self.fr_timer.timeout.connect(self.keep_fr_active)
       
        self.skl_timer = QTimer()
        self.skl_timer.timeout.connect(self.keep_skl_active)
       
        self.pot_timer = QTimer()
        self.pot_timer.timeout.connect(self.keep_pot_nop)
      
        opera_logger.log_event(
            EventLevel.SUCCESS,
            "✅ v1.0!",
            "OPERA"
        )
        
        # Conectar sinal para F8
        self.toggle_visibility_signal.connect(self._toggle_visibility)
        
        self.setup_hotkeys()
        
        # KeyAuth integration
        self.keyauthapp = api("NBC", "9PNQvqtqsi", "1.0", get_checksum())
        
        try:
            self.keyauthapp.log("Aplicativo iniciado")
        except:
            pass
            
        self.license_timer = QTimer()
        self.license_timer.timeout.connect(self.check_license_status)
        self.license_timer.start(10000)  # Verificar a cada 10 segundos
        
        # Esconder painel até autenticação
        self.main_frame.hide()
        self.authenticate()
   
    def authenticate(self):
        """Autenticação obrigatória - painel bloqueado até validação"""
        key = self.load_license()
        if key:
            if self.keyauthapp.license(key):
                # Licença válida - liberar painel
                self.is_authenticated = True
                self.main_frame.show()
                opera_logger.log_event(EventLevel.SUCCESS, "✅ Licença válida - Painel liberado", "KEYAUTH")
                try:
                    self.keyauthapp.log("Licença carregada com sucesso")
                except:
                    pass
                return
            else:
                # Licença inválida - forçar nova autenticação
                opera_logger.log_event(EventLevel.ERROR, "❌ Licença local inválida", "KEYAUTH")
                try:
                    self.keyauthapp.log("Falha ao validar licença local")
                except:
                    pass
                # Deletar licença inválida
                try:
                    os.remove(OPERA_LICENSE)
                    os.remove(OPERA_LICENSE_BAK)
                except:
                    pass
        
        # Loop até autenticação válida
        while not self.is_authenticated:
            dialog = QDialog(self)
            dialog.setWindowTitle("🔐 Ativação de Licença - Opera")
            dialog.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowStaysOnTopHint)
            dialog.setModal(True)
            dialog.setFixedSize(350, 150)
            
            layout = QVBoxLayout()
            layout.setSpacing(10)
            layout.setContentsMargins(20, 20, 20, 20)
            
            label = QLabel("🔑 Insira sua chave de licença:")
            label.setStyleSheet("font-size: 13px; font-weight: bold;")
            
            key_input = QLineEdit()
            key_input.setPlaceholderText("XXXX-XXXX-XXXX-XXXX")
            key_input.setStyleSheet("""
                QLineEdit {
                    padding: 8px;
                    border: 2px solid #FF1B2D;
                    border-radius: 5px;
                    font-size: 12px;
                }
            """)
            
            button_layout = QHBoxLayout()
            
            button = QPushButton("✓ Ativar")
            button.setStyleSheet("""
                QPushButton {
                    background: #FF1B2D;
                    color: white;
                    padding: 8px 20px;
                    border: none;
                    border-radius: 5px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: #cc1624;
                }
            """)
            button.clicked.connect(lambda: self.activate_license(key_input.text(), dialog))
            
            exit_button = QPushButton("✕ Sair")
            exit_button.setStyleSheet("""
                QPushButton {
                    background: #666;
                    color: white;
                    padding: 8px 20px;
                    border: none;
                    border-radius: 5px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: #444;
                }
            """)
            exit_button.clicked.connect(lambda: self.force_exit())
            
            button_layout.addWidget(button)
            button_layout.addWidget(exit_button)
            
            layout.addWidget(label)
            layout.addWidget(key_input)
            layout.addLayout(button_layout)
            
            dialog.setLayout(layout)
            
            result = dialog.exec()
            
            # Se dialog foi fechado sem autenticar, sair do programa
            if not self.is_authenticated:
                opera_logger.log_event(EventLevel.WARNING, "Autenticação cancelada pelo usuário", "KEYAUTH")
                self.force_exit()
                break
    
    def activate_license(self, key, dialog):
        """Ativa licença e libera painel apenas se válida"""
        if not key or len(key.strip()) == 0:
            QMessageBox.warning(dialog, "⚠️ Erro", "Por favor, insira uma chave válida!")
            return
        
        if self.keyauthapp.license(key.strip()):
            self.save_license(key.strip())
            self.is_authenticated = True
            self.main_frame.show()  # Liberar painel
            
            opera_logger.log_event(EventLevel.SUCCESS, "✅ Licença ativada - Painel liberado", "KEYAUTH")
            try:
                self.keyauthapp.log("Licença ativada com sucesso")
            except:
                pass
            
            dialog.close()
            QMessageBox.information(self, "✓ Sucesso", "Licença ativada com sucesso!\nBem-vindo ao Opera!")
        else:
            QMessageBox.critical(dialog, "❌ Erro", "Licença inválida, expirada ou problema de HWID!\n\nVerifique sua chave e tente novamente.")
            try:
                self.keyauthapp.log("Tentativa de ativação falhou")
            except:
                pass
    
    def force_exit(self):
        """Força saída do programa"""
        opera_logger.log_event(EventLevel.WARNING, "Programa encerrado - Sem autenticação", "KEYAUTH")
        try:
            self.keyauthapp.log("Programa encerrado sem autenticação")
        except:
            pass
        QApplication.quit()
        sys.exit(0)
    
    def load_license(self):
        try:
            with open(OPERA_LICENSE, "r") as f:
                enc_key = f.read()
            key = decode_string(enc_key)
            return key if key else None
        except:
            return None
    
    def save_license(self, key):
        enc_key = encode_string(key)
        try:
            with open(OPERA_LICENSE, "w") as f:
                f.write(enc_key)
            with open(OPERA_LICENSE_BAK, "w") as f:
                f.write(enc_key)
        except:
            pass
    
    def check_license_status(self):
        """Verificação rigorosa do status da licença - bloqueia painel se inválida"""
        if not self.keyauthapp.check():
            # Licença inválida detectada
            opera_logger.log_event(EventLevel.ERROR, "❌ LICENÇA INVÁLIDA DETECTADA!", "KEYAUTH")
            try:
                self.keyauthapp.log("Licença inválida detectada durante verificação")
            except:
                pass
            
            # Desabilitar TODAS as funções
            self.disable_all_features()
            
            # Esconder painel
            self.main_frame.hide()
            self.is_authenticated = False
            
            # Deletar licença inválida
            try:
                os.remove(OPERA_LICENSE)
                os.remove(OPERA_LICENSE_BAK)
            except:
                pass
            
            # Mostrar aviso e voltar para tela de autenticação
            QMessageBox.critical(
                self, 
                "❌ Licença Inválida", 
                "Sua licença expirou ou foi revogada!\n\nO programa será bloqueado.\nInsira uma nova chave válida."
            )
            
            # Forçar nova autenticação
            self.authenticate()
    
    def disable_all_features(self):
        """Desabilita todas as features quando licença fica inválida"""
        # Parar todos os timers
        self.fr_timer.stop()
        self.skl_timer.stop()
        self.pot_timer.stop()
        self.license_timer.stop()
        
        # Desmarcar todos os checkboxes
        self.ext1_check.setChecked(False)
        self.ext2_check.setChecked(False)
        self.ext3_check.setChecked(False)
        
        # Desabilitar todos os checkboxes
        self.ext1_check.setEnabled(False)
        self.ext2_check.setEnabled(False)
        self.ext3_check.setEnabled(False)
        
        # Reverter POT se estiver ativo
        if self.pot_active:
            self.revert_pot_nop()
        
        # Reverter FR para 0
        if self.fr_address:
            try:
                self.memory_writer.force_write_int(self.fr_address, 0)
            except:
                pass
        
        opera_logger.log_event(EventLevel.WARNING, "⚠️ Todas as features desabilitadas", "SECURITY")
   
    def setup_hotkeys(self):
        keyboard.add_hotkey(self.hotkeys['fr'], lambda: self.ext1_check.setChecked(not self.ext1_check.isChecked()))
        keyboard.add_hotkey(self.hotkeys['pot'], lambda: self.ext2_check.setChecked(not self.ext2_check.isChecked()))
        keyboard.add_hotkey(self.hotkeys['skl'], lambda: self.ext3_check.setChecked(not self.ext3_check.isChecked()))
        keyboard.add_hotkey('f8', lambda: self.toggle_visibility_signal.emit())
        opera_logger.log_event(EventLevel.INFO, "Hotkeys configuradas", "HOTKEY")
    
    def _toggle_visibility(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.raise_()
            self.activateWindow()
   
    def open_hotkey_settings(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Configurações de Hotkeys")
        layout = QFormLayout()
        
        fr_edit = QKeySequenceEdit(QKeySequence(self.hotkeys['fr']))
        layout.addRow("FR:", fr_edit)
        
        pot_edit = QKeySequenceEdit(QKeySequence(self.hotkeys['pot']))
        layout.addRow("POT:", pot_edit)
        
        skl_edit = QKeySequenceEdit(QKeySequence(self.hotkeys['skl']))
        layout.addRow("SKL:", skl_edit)
        
        save_btn = QPushButton("Salvar")
        save_btn.clicked.connect(lambda: self.save_hotkeys(fr_edit.keySequence().toString(), pot_edit.keySequence().toString(), skl_edit.keySequence().toString(), dialog))
        
        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(save_btn)
        dialog.setLayout(main_layout)
        dialog.exec()
   
    def save_hotkeys(self, fr, pot, skl, dialog):
        self.hotkeys = {'fr': fr, 'pot': pot, 'skl': skl}
        opera_prefs['hotkeys'] = self.hotkeys
        save_preferences(opera_prefs)
        self.setup_hotkeys()  # Reconfigura hotkeys
        dialog.close()
        opera_logger.log_event(EventLevel.INFO, "Hotkeys atualizadas e salvas", "HOTKEY")
   
    def _create_ui(self):
        """Cria interface"""
        self.main_frame = QFrame(self)
        self.main_frame.setGeometry(0, 0, 460, 550)
        self.main_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1a1a1a,
                    stop:1 #0a0a0a);
                border-radius: 15px;
                border: 2px solid #FF1B2D;
            }
        """)
      
        layout = QVBoxLayout(self.main_frame)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
      
        # Header
        header_frame = QFrame()
        header_frame.setFixedHeight(80)
        header_frame.setCursor(Qt.CursorShape.SizeAllCursor)
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(255, 27, 45, 200),
                    stop:0.5 rgba(255, 27, 45, 160),
                    stop:1 rgba(255, 27, 45, 200));
                border-radius: 10px;
                border: 2px solid #FF1B2D;
            }
        """)
      
        self.header = header_frame
        header_frame.installEventFilter(self)
      
        header_layout = QVBoxLayout(header_frame)
        header_layout.setSpacing(2)
        header_layout.setContentsMargins(8, 8, 8, 8)
      
        title_bar = QHBoxLayout()
      
        title = QLabel("Opera Internet Browser")
        title.setStyleSheet("""
            color: white;
            font-size: 18px;
            font-weight: bold;
        """)
      
        hotkey_btn = QPushButton("⌨️")
        hotkey_btn.setFixedSize(28, 28)
        hotkey_btn.setToolTip("Configurações de Hotkeys\nF8 = Esconder/Mostrar painel")
        hotkey_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 30);
                color: white;
                border: 2px solid rgba(255, 255, 255, 80);
                border-radius: 14px;
                font-size: 18px;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 60);
            }
        """)
        hotkey_btn.clicked.connect(self.open_hotkey_settings)
      
        minimize_btn = QPushButton("_")
        minimize_btn.setFixedSize(28, 28)
        minimize_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 30);
                color: white;
                border: 2px solid rgba(255, 255, 255, 80);
                border-radius: 14px;
                font-size: 18px;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 60);
            }
        """)
        minimize_btn.clicked.connect(self.showMinimized)
      
        close_btn = QPushButton("×")
        close_btn.setFixedSize(28, 28)
        close_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 30);
                color: white;
                border: 2px solid rgba(255, 255, 255, 80);
                border-radius: 14px;
                font-size: 22px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 60);
            }
        """)
        close_btn.clicked.connect(self.close)
      
        title_bar.addWidget(title)
        title_bar.addStretch()
        title_bar.addWidget(hotkey_btn)
        title_bar.addWidget(minimize_btn)
        title_bar.addWidget(close_btn)
      
        self.status_lbl = QLabel("Waiting for process...")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setStyleSheet(
            "color: rgba(255,255,255,180); font-size: 11px; font-weight: bold;"
        )
      
        header_layout.addLayout(title_bar)
        header_layout.addWidget(self.status_lbl)
      
        # Extensions
        extensions_frame = QFrame()
        extensions_frame.setStyleSheet("""
            QFrame {
                background: rgba(30, 30, 30, 150);
                border: 2px solid #FF1B2D;
                border-radius: 10px;
            }
        """)
        ext_layout = QVBoxLayout(extensions_frame)
        ext_layout.setContentsMargins(10, 10, 10, 10)
        ext_layout.setSpacing(8)
      
        self.ext1_check = QCheckBox("⚡ FR ")
        self.ext1_check.setEnabled(False)
        self.ext1_check.setFixedHeight(35)
        self.ext1_check.setStyleSheet("""
            QCheckBox {
                color: #FF1B2D;
                font-size: 14px;
                font-weight: bold;
                spacing: 10px;
            }
            QCheckBox::indicator {
                width: 22px;
                height: 22px;
                border-radius: 11px;
                border: 2px solid #FF1B2D;
            }
            QCheckBox::indicator:checked {
                background: #FF1B2D;
            }
        """)
        self.ext1_check.stateChanged.connect(self.toggle_fr)
      
        self.ext2_check = QCheckBox("🔥 POT ")
        self.ext2_check.setEnabled(False)
        self.ext2_check.setFixedHeight(35)
        self.ext2_check.setStyleSheet("""
            QCheckBox {
                color: #FF1B2D;
                font-size: 14px;
                font-weight: bold;
                spacing: 10px;
            }
            QCheckBox::indicator {
                width: 22px;
                height: 22px;
                border-radius: 11px;
                border: 2px solid #FF1B2D;
            }
            QCheckBox::indicator:checked {
                background: #FF1B2D;
            }
        """)
        self.ext2_check.stateChanged.connect(self.toggle_pot)
      
        self.ext3_check = QCheckBox("🎯 SKL 100%")
        self.ext3_check.setEnabled(False)
        self.ext3_check.setFixedHeight(35)
        self.ext3_check.setStyleSheet("""
            QCheckBox {
                color: #FF1B2D;
                font-size: 14px;
                font-weight: bold;
                spacing: 10px;
            }
            QCheckBox::indicator {
                width: 22px;
                height: 22px;
                border-radius: 11px;
                border: 2px solid #FF1B2D;
            }
            QCheckBox::indicator:checked {
                background: #FF1B2D;
            }
        """)
        self.ext3_check.stateChanged.connect(self.toggle_skl)
      
        ext_layout.addWidget(self.ext1_check)
        ext_layout.addWidget(self.ext2_check)
        ext_layout.addWidget(self.ext3_check)
      
        self.debug_console = DebugConsole()
      
        layout.addWidget(header_frame)
        layout.addWidget(extensions_frame)
        layout.addWidget(self.debug_console)
        layout.addStretch()
   
    def resolve_skill_base(self) -> Optional[int]:
        """
        Resolve o base do SKL com soma direta
        Game.exe + 554DD30 + 128
        """
        try:
            # Calcular endereço base com soma direta
            skill_base = self.proc_base + 0x554DD30 + 0x128
           
            opera_logger.log_event(
                EventLevel.DEBUG,
                f"📍 SKL base calculado com soma direta: {hex(self.proc_base)} + 0x554DD30 + 0x128 = {hex(skill_base)}",
                "SKL"
            )
           
            # Verificar se o endereço é válido tentando ler 1 byte
            test_read = self.memory_writer.read_byte_safe(skill_base)
            if test_read is None:
                opera_logger.log_event(
                    EventLevel.ERROR,
                    f"❌ Endereço base inválido: {hex(skill_base)}",
                    "SKL"
                )
                return None
           
            opera_logger.log_event(
                EventLevel.SUCCESS,
                f"✓ SKL base válido: {hex(skill_base)}",
                "SKL"
            )
           
            return skill_base
           
        except Exception as e:
            opera_logger.log_event(
                EventLevel.ERROR,
                f"❌ Erro ao resolver base SKL: {e}",
                "SKL"
            )
            return None
   
    def toggle_fr(self):
        """Toggle FR - Mantém valor 1 quando ativo - BLOQUEADO SEM AUTENTICAÇÃO"""
        if not self.is_authenticated:
            self.ext1_check.setChecked(False)
            QMessageBox.warning(self, "🚫 Acesso Negado", "Você precisa estar autenticado para usar esta função!")
            opera_logger.log_event(EventLevel.ERROR, "Tentativa de usar FR sem autenticação", "SECURITY")
            return
        
        if not self.connected or not self.fr_address:
            return
       
        active = self.ext1_check.isChecked()
       
        if active:
            self.fr_timer.start(100)
            opera_logger.log_event(EventLevel.SUCCESS, "FR ATIVADO", "FR")
            try:
                self.keyauthapp.log("FR ativado")
            except:
                pass
        else:
            self.fr_timer.stop()
            if self.memory_writer.force_write_int(self.fr_address, 0):
                opera_logger.log_event(EventLevel.INFO, "FR DESATIVADO", "FR")
                try:
                    self.keyauthapp.log("FR desativado")
                except:
                    pass
   
    def keep_fr_active(self):
        """Mantém FR ativo com valor 1"""
        if not self.ext1_check.isChecked() or not self.fr_address:
            return
       
        try:
            current = self.memory_writer.read_int_safe(self.fr_address)
           
            if current is None:
                return
           
            if current != 1:
                if self.memory_writer.force_write_int(self.fr_address, 1):
                    opera_logger.log_event(
                        EventLevel.WARNING,
                        f"FR restaurado: {current} → 1",
                        "FR-KEEP"
                    )
        except:
            pass
   
    def toggle_pot(self):
        """Toggle POT - BLOQUEADO SEM AUTENTICAÇÃO"""
        if not self.is_authenticated:
            self.ext2_check.setChecked(False)
            QMessageBox.warning(self, "🚫 Acesso Negado", "Você precisa estar autenticado para usar esta função!")
            opera_logger.log_event(EventLevel.ERROR, "Tentativa de usar POT sem autenticação", "SECURITY")
            return
        
        if not self.connected or not self.pot_addr:
            return
       
        if self.ext2_check.isChecked():
            self.apply_pot_nop()
        else:
            self.revert_pot_nop()
   
    def apply_pot_nop(self):
        """Aplica NOP no endereço POT"""
        try:
            current = self.memory_writer.read_byte_safe(self.pot_addr)
           
            if current == 0x90:
                self.pot_active = True
                self.pot_timer.start(100)
                opera_logger.log_event(EventLevel.SUCCESS, "POT NOP já aplicado", "POT")
                try:
                    self.keyauthapp.log("POT NOP já aplicado")
                except:
                    pass
                return
           
            self.pot_orig = current
           
            if self.memory_writer.force_write_byte(self.pot_addr, 0x90):
                self.pot_active = True
                self.pot_timer.start(100)
                opera_logger.log_event(
                    EventLevel.SUCCESS,
                    f"POT NOP aplicado: {hex(current)} → 0x90",
                    "POT"
                )
                try:
                    self.keyauthapp.log(f"POT NOP aplicado: {hex(current)} → 0x90")
                except:
                    pass
            else:
                self.ext2_check.setChecked(False)
               
        except Exception as e:
            opera_logger.log_event(EventLevel.ERROR, f"POT erro: {e}", "POT")
            try:
                self.keyauthapp.log(f"POT erro: {e}")
            except:
                pass
            self.ext2_check.setChecked(False)
   
    def revert_pot_nop(self):
        """Reverte POT para valor original"""
        if not self.pot_orig or not self.pot_addr:
            return
       
        self.pot_timer.stop()
       
        if self.memory_writer.write_byte_safe(self.pot_addr, self.pot_orig):
            self.pot_active = False
            opera_logger.log_event(EventLevel.INFO, "POT revertido", "POT")
            try:
                self.keyauthapp.log("POT revertido")
            except:
                pass
   
    def keep_pot_nop(self):
        """Mantém POT como NOP"""
        if not self.pot_active or not self.pot_addr:
            return
       
        try:
            current = self.memory_writer.read_byte_safe(self.pot_addr)
           
            if current is not None and current != 0x90:
                self.memory_writer.force_write_byte(self.pot_addr, 0x90)
        except:
            pass
   
    def toggle_skl(self):
        """Toggle SKL - Escreve 0 nos 16 skills - BLOQUEADO SEM AUTENTICAÇÃO"""
        if not self.is_authenticated:
            self.ext3_check.setChecked(False)
            QMessageBox.warning(self, "🚫 Acesso Negado", "Você precisa estar autenticado para usar esta função!")
            opera_logger.log_event(EventLevel.ERROR, "Tentativa de usar SKL sem autenticação", "SECURITY")
            return
        
        if not self.connected or not self.skill_addresses:
            opera_logger.log_event(
                EventLevel.WARNING,
                "SKL addresses not resolved!",
                "SKL"
            )
            return
       
        active = self.ext3_check.isChecked()
       
        if active:
            self.apply_skill_zero()
            self.skl_timer.start(100)
        else:
            self.skl_timer.stop()
            opera_logger.log_event(EventLevel.INFO, "SKL timer parado", "SKL")
            try:
                self.keyauthapp.log("SKL desativado")
            except:
                pass
   
    def apply_skill_zero(self):
        """Escreve 0 em todos os 16 skills"""
        try:
            success_count = 0
           
            for i, addr in enumerate(self.skill_addresses):
                if self.memory_writer.force_write_byte(addr, 0):
                    success_count += 1
                    opera_logger.log_event(
                        EventLevel.SUCCESS,
                        f"SKL {i+1}/16: OK @ {hex(addr)} → 0",
                        "SKL"
                    )
                else:
                    opera_logger.log_event(
                        EventLevel.ERROR,
                        f"SKL {i+1}/16: FALHOU @ {hex(addr)}",
                        "SKL"
                    )
           
            if success_count == 16:
                self.status_lbl.setText("✅ SKL: 16/16 SUCCESS!")
                opera_logger.log_event(
                    EventLevel.SUCCESS,
                    "SKL: Todos 16 skills zerados!",
                    "SKL"
                )
                try:
                    self.keyauthapp.log("SKL ativado com sucesso")
                except:
                    pass
            else:
                self.status_lbl.setText(f"⚠️ SKL: {success_count}/16")
                opera_logger.log_event(
                    EventLevel.WARNING,
                    f"SKL: Apenas {success_count}/16 zerados",
                    "SKL"
                )
           
            QTimer.singleShot(3000, lambda: self.status_lbl.setText("✓ CONNECTED"))
           
        except Exception as e:
            opera_logger.log_event(EventLevel.ERROR, f"SKL erro: {e}", "SKL")
            try:
                self.keyauthapp.log(f"SKL erro: {e}")
            except:
                pass
            self.ext3_check.setChecked(False)
   
    def keep_skl_active(self):
        """Mantém skills zerados"""
        if not self.ext3_check.isChecked() or not self.skill_addresses:
            return
       
        try:
            for addr in self.skill_addresses:
                current = self.memory_writer.read_byte_safe(addr)
               
                if current is not None and current != 0:
                    self.memory_writer.force_write_byte(addr, 0)
        except:
            pass
   
    def on_process_found(self, handle, base):
        """Quando processo encontrado, resolve ponteiros - APENAS SE AUTENTICADO"""
        # VERIFICAÇÃO CRÍTICA: Bloquear se não autenticado
        if not self.is_authenticated:
            opera_logger.log_event(
                EventLevel.ERROR,
                "🚫 Processo detectado mas SEM AUTENTICAÇÃO - bloqueado!",
                "SECURITY"
            )
            return
        
        self.mem_handle = handle
        self.proc_base = base
        self.connected = True
       
        self.memory_writer = AdvancedMemoryWriter(handle, max_retries=5)
       
        opera_logger.log_event(
            EventLevel.INFO,
            f"🎯 Base do processo: {hex(base)}",
            "MEMORY"
        )
        try:
            self.keyauthapp.log(f"Processo encontrado: {hex(base)}")
        except:
            pass
       
        # ===== FR - Endereço direto =====
        self.fr_address = base + 0x5537C10
        opera_logger.log_event(
            EventLevel.SUCCESS,
            f"FR resolvido: {hex(self.fr_address)}",
            "FR"
        )
       
        # ===== SKL - Soma direta =====
        skill_base = self.resolve_skill_base()
       
        if skill_base:
            self.skill_addresses = []
            for i in range(16):
                addr = skill_base + (i * 0x210)
                self.skill_addresses.append(addr)
                opera_logger.log_event(
                    EventLevel.DEBUG,
                    f"SKL[{i+1}]: {hex(addr)}",
                    "SKL"
                )
           
            opera_logger.log_event(
                EventLevel.SUCCESS,
                f"✓ Todos os 16 skills resolvidos!",
                "SKL"
            )
            self.ext3_check.setEnabled(True)
        else:
            opera_logger.log_event(
                EventLevel.ERROR,
                "❌ Falha ao resolver base SKL!",
                "SKL"
            )
       
        # ===== POT - Endereço direto =====
        self.pot_addr = base + 0x27DF73
        opera_logger.log_event(
            EventLevel.SUCCESS,
            f"POT resolvido: {hex(self.pot_addr)}",
            "POT"
        )
       
        # Bypass anti-cheat
        try:
            ac_addr = base + 0xD7395
            self.memory_writer.unprotect_memory(ac_addr, 1)
            current = self.memory_writer.read_byte_safe(ac_addr)
           
            if current == 0xE9:
                self.memory_writer.write_byte_safe(ac_addr, 0xEB)
                opera_logger.log_event(EventLevel.SUCCESS, "Anti-cheat bypassed", "AC")
                try:
                    self.keyauthapp.log("Anti-cheat bypassed")
                except:
                    pass
        except:
            pass
       
        self.ext1_check.setEnabled(True)
        self.ext2_check.setEnabled(True)
       
        self.status_lbl.setText("✓ CONNECTED ")
        self.status_lbl.setStyleSheet("""
            color: white;
            font-size: 12px;
            font-weight: bold;
        """)
       
        opera_logger.log_event(
            EventLevel.SUCCESS,
            "✅ Processo conectado!",
            "MEMORY"
        )
   
    def on_process_lost(self):
        """Quando processo perdido"""
        self.connected = False
        self.memory_writer = None
       
        self.fr_timer.stop()
        self.skl_timer.stop()
        self.pot_timer.stop()
       
        self.ext1_check.setEnabled(False)
        self.ext1_check.setChecked(False)
        self.ext2_check.setEnabled(False)
        self.ext2_check.setChecked(False)
        self.ext3_check.setEnabled(False)
        self.ext3_check.setChecked(False)
       
        self.fr_address = None
        self.skill_addresses = []
        self.pot_addr = None
        self.pot_active = False
       
        self.status_lbl.setText("× WAITING...")
       
        opera_logger.log_event(EventLevel.WARNING, "Process disconnected", "MEMORY")
        try:
            self.keyauthapp.log("Processo desconectado")
        except:
            pass
   
    def eventFilter(self, obj, event):
        """Event filter para drag"""
        if obj == self.header:
            if event.type() == QEvent.Type.MouseButtonPress:
                if event.button() == Qt.MouseButton.LeftButton:
                    self.dragging = True
                    self.drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
                    return True
            elif event.type() == QEvent.Type.MouseMove:
                if self.dragging:
                    self.move(event.globalPosition().toPoint() - self.drag_pos)
                    return True
            elif event.type() == QEvent.Type.MouseButtonRelease:
                if event.button() == Qt.MouseButton.LeftButton:
                    self.dragging = False
                    return True
        return super().eventFilter(obj, event)
   
    def shutdown(self):
        """Shutdown seguro"""
        if self.pot_active:
            self.revert_pot_nop()
       
        self.watcher.stop_watching()
        self.watcher.wait(2000)
       
        if hasattr(self, 'keyauthapp'):
            try:
                self.keyauthapp.logout()
            except:
                pass
       
        QApplication.quit()
   
    def closeEvent(self, event):
        self.shutdown()
        event.accept()
# ================= ENTRY POINT =================
if __name__ == "__main__":
    if not check_admin_rights():
        QMessageBox.critical(
            None,
            "Administrator Required",
            "⚠️ Requires Administrator privileges!\n\n"
            "Right-click and select 'Run as administrator'"
        )
        sys.exit(1)
  
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme="dark_red.xml")
  
    window = OperaExtensionManager()
    window.show()
  
    sys.exit(app.exec())
    input("Pressione Enter para fechar...")
