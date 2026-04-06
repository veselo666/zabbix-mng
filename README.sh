#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import re
import os
import sys
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

# ------------------ НАСТРОЙКА ЛОГИРОВАНИЯ ------------------
LOG_FILE = "zabbix_ldap_sync.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
# Дублируем вывод ошибок в консоль
console = logging.StreamHandler()
console.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# ------------------ ЗАГРУЗКА ПЕРЕМЕННЫХ ------------------
try:
    from dotenv import load_dotenv
    load_dotenv("config.env")
except ImportError:
    logging.warning("Модуль python-dotenv не установлен. Используются системные переменные окружения.")

# Обязательные переменные
REQUIRED_VARS = [
    "LDAP_URI", "LDAP_BASE", "LDAP_USER", "LDAP_PASS",
    "ZABBIX_URL", "ZABBIX_TOKEN", "LDAP_GROUP_PREFIX",
    "ROLE_VIEWER", "ROLE_EDITOR", "USER_DIRECTORY"
]

missing_vars = [var for var in REQUIRED_VARS if not os.getenv(var)]
if missing_vars:
    error_msg = f"Отсутствуют обязательные переменные в config.env: {', '.join(missing_vars)}"
    logging.error(error_msg)
    sys.exit(1)

LDAP_URI = os.getenv("LDAP_URI")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")

PREFIX = os.getenv("LDAP_GROUP_PREFIX")

ROLE_VIEWER = os.getenv("ROLE_VIEWER")
ROLE_EDITOR = os.getenv("ROLE_EDITOR")

USER_DIRECTORY = os.getenv("USER_DIRECTORY")

REGEX = r"<<>>"

# ------------------ КЛАСС ДЛЯ РАБОТЫ С ZABBIX API ------------------
class ZabbixAPI:
    """Класс для взаимодействия с Zabbix API с использованием Bearer-токена."""
    
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.id = 0
        self._verify_connection()

    def _call(self, method: str, params: Dict, auth_required: bool = True) -> Any:
        """Универсальный вызов метода Zabbix API."""
        self.id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.id
        }
        
        headers = {'Content-Type': 'application/json-rpc'}
        if auth_required:
            headers['Authorization'] = f'Bearer {self.token}'
        
        try:
            response = requests.post(
                self.url, 
                json=payload, 
                headers=headers, 
                verify=False, 
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.Timeout:
            raise Exception(f"Таймаут при подключении к Zabbix API: {self.url}")
        except requests.exceptions.ConnectionError:
            raise Exception(f"Ошибка соединения с Zabbix API: {self.url}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Ошибка HTTP-запроса: {e}")
        except json.JSONDecodeError as e:
            raise Exception(f"Неверный JSON-ответ от Zabbix: {e}. Ответ: {response.text[:200]}")
        
        if "error" in data:
            error_msg = data['error'].get('data', 'Неизвестная ошибка API')
            raise Exception(f"Zabbix API error: {data['error']['code']} - {error_msg}")
        if "result" not in data:
            raise Exception(f"Zabbix API не вернул 'result' в методе {method}. Ответ: {data}")
        
        return data["result"]

    def _verify_connection(self):
        """Проверяет соединение с API без использования авторизации."""
        try:
            # Специальный вызов без заголовка авторизации
            result = self._call("apiinfo.version", [], auth_required=False)
            logging.info(f"Успешное подключение к Zabbix API. Версия API: {result}")
            return True
        except Exception as e:
            logging.error(f"Не удалось подключиться к Zabbix API: {e}")
            raise

    def get_roles(self) -> Dict[str, str]:
        """Получает словарь ролей: имя -> ID."""
        roles = self._call("role.get", {"output": ["roleid", "name"]})
        return {role["name"]: role["roleid"] for role in roles}

    def get_user_directory_id(self, directory_name: str) -> Optional[str]:
        """Возвращает ID каталога пользователей по его имени."""
        directories = self._call("userdirectory.get", {"output": "extend"})
        for d in directories:
            if d["name"] == directory_name:
                return d["userdirectoryid"]
        return None

    def get_user_group(self, group_name: str) -> Optional[Dict]:
        """Возвращает информацию о группе пользователей."""
        groups = self._call("usergroup.get", {"filter": {"name": group_name}})
        return groups[0] if groups else None

    def create_user_group(self, group_name: str) -> str:
        """Создаёт новую группу пользователей и возвращает её ID."""
        result = self._call("usergroup.create", {"name": group_name})
        return result["usrgrpids"][0]

    def get_ldap_group_mapping(self, directory_id: str, ldap_group_name: str) -> Optional[Dict]:
        """Проверяет существование маппинга LDAP-группы."""
        mappings = self._call("userdirectorygroup.get", {
            "filter": {"name": ldap_group_name},
            "userdirectoryids": directory_id
        })
        return mappings[0] if mappings else None

    def create_ldap_group_mapping(self, directory_id: str, ldap_group_name: str, 
                                   role_id: str, user_group_id: str) -> Dict:
        """Создаёт маппинг LDAP-группы на группу Zabbix."""
        return self._call("userdirectorygroup.create", {
            "userdirectoryid": directory_id,
            "name": ldap_group_name,
            "roleid": role_id,
            "usrgrps": [{"usrgrpid": user_group_id}]
        })

# ------------------ РАБОТА С LDAP ------------------
def get_ldap_groups() -> List[Dict[str, str]]:
    """Возвращает список групп из LDAP, соответствующих регулярному выражению."""
    # Настройки соединения
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    
    conn = None
    try:
        conn = ldap.initialize(LDAP_URI)
        # Установка таймаута для соединения
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        conn.simple_bind_s(LDAP_USER, LDAP_PASS)
        logging.info(f"Успешное подключение к LDAP: {LDAP_URI}")
    except ldap.LDAPError as e:
        error_msg = f"Ошибка подключения/аутентификации LDAP: {e}"
        logging.error(error_msg)
        raise Exception(error_msg)
    
    try:
        search_filter = f"(cn={PREFIX}*)"
        logging.debug(f"LDAP поиск: base={LDAP_BASE}, filter={search_filter}")
        
        result = conn.search_s(
            LDAP_BASE,
            ldap.SCOPE_SUBTREE,
            search_filter,
            ["cn"]
        )
    except ldap.LDAPError as e:
        error_msg = f"Ошибка поиска в LDAP: {e}"
        logging.error(error_msg)
        raise Exception(error_msg)
    finally:
        if conn:
            conn.unbind()
    
    groups = []
    for dn, entry in result:
        if not entry or "cn" not in entry:
            continue
        
        # Декодирование имени группы (поддержка байтов и строк)
        cn_value = entry["cn"][0]
        if isinstance(cn_value, bytes):
            cn = cn_value.decode("utf-8")
        else:
            cn = cn_value
        
        match = re.match(REGEX, cn)
        if match:
            groups.append({
                "ldap_name": cn,
                "system": match.group(1),
                "type": match.group(2)
            })
            logging.debug(f"Найдена группа: {cn} (system={match.group(1)}, type={match.group(2)})")
    
    logging.info(f"Найдено групп в LDAP, соответствующих шаблону: {len(groups)}")
    return groups

# ------------------ ОСНОВНАЯ ЛОГИКА СИНХРОНИЗАЦИИ ------------------
def main():
    logging.info("=== НАЧАЛО СИНХРОНИЗАЦИИ LDAP -> ZABBIX ===")
    start_time = datetime.now()
    
    try:
        # 1. Инициализация Zabbix API
        logging.info("Инициализация подключения к Zabbix API...")
        zbx = ZabbixAPI(ZABBIX_URL, ZABBIX_TOKEN)
        
        # 2. Получение ролей
        logging.info("Получение списка ролей...")
        role_map = zbx.get_roles()
        
        if ROLE_VIEWER not in role_map:
            raise Exception(f"Роль '{ROLE_VIEWER}' не найдена в Zabbix. Доступные роли: {list(role_map.keys())}")
        if ROLE_EDITOR not in role_map:
            raise Exception(f"Роль '{ROLE_EDITOR}' не найдена в Zabbix. Доступные роли: {list(role_map.keys())}")
        
        logging.info(f"Найдены роли: viewer='{ROLE_VIEWER}' (id={role_map[ROLE_VIEWER]}), "
                     f"editor='{ROLE_EDITOR}' (id={role_map[ROLE_EDITOR]})")
        
        # 3. Получение ID каталога пользователей
        logging.info(f"Поиск каталога пользователей '{USER_DIRECTORY}'...")
        directory_id = zbx.get_user_directory_id(USER_DIRECTORY)
        if not directory_id:
            raise Exception(f"Каталог пользователей '{USER_DIRECTORY}' не найден в Zabbix. "
                          f"Проверьте название в настройках Zabbix (раздел Administration -> Authentication -> LDAP settings)")
        
        logging.info(f"Найден каталог пользователей: ID={directory_id}")
        
        # 4. Получение групп из LDAP
        logging.info("Получение групп из LDAP...")
        ldap_groups = get_ldap_groups()
        
        if not ldap_groups:
            logging.warning("Не найдено ни одной группы LDAP, соответствующих шаблону. "
                           f"Проверьте префикс: '{PREFIX}' и регулярное выражение.")
            return
        
        # 5. Синхронизация: создание групп и маппингов
        success_count = 0
        skip_count = 0
        error_count = 0
        
        for lg in ldap_groups:
            try:
                system = lg["system"]
                gtype = lg["type"]
                user_group_name = f"{system}-{gtype}".lower()
                role_name = ROLE_VIEWER if gtype == "viewers" else ROLE_EDITOR
                role_id = role_map[role_name]
                
                logging.info(f"--- Обработка: {lg['ldap_name']} -> {user_group_name} (роль {role_name})")
                
                # Поиск или создание группы пользователей Zabbix
                existing_group = zbx.get_user_group(user_group_name)
                if existing_group:
                    user_group_id = existing_group["usrgrpid"]
                    logging.debug(f"Группа '{user_group_name}' уже существует (ID={user_group_id})")
                else:
                    user_group_id = zbx.create_user_group(user_group_name)
                    logging.info(f"Создана новая группа пользователей: '{user_group_name}' (ID={user_group_id})")
                
                # Проверка существующего маппинга
                existing_mapping = zbx.get_ldap_group_mapping(directory_id, lg["ldap_name"])
                if existing_mapping:
                    logging.info(f"Маппинг для '{lg['ldap_name']}' уже существует (ID={existing_mapping.get('userdirectorygroupid')}). Пропускаем.")
                    skip_count += 1
                    continue
                
                # Создание маппинга
                zbx.create_ldap_group_mapping(directory_id, lg["ldap_name"], role_id, user_group_id)
                logging.info(f"Создан маппинг: {lg['ldap_name']} -> {user_group_name} (роль {role_name})")
                success_count += 1
                
            except Exception as e:
                logging.error(f"Ошибка при обработке группы {lg.get('ldap_name', 'unknown')}: {e}")
                error_count += 1
        
        # Итоговый отчёт
        elapsed = datetime.now() - start_time
        logging.info(f"=== СИНХРОНИЗАЦИЯ ЗАВЕРШЕНА за {elapsed.total_seconds():.2f} секунд ===")
        logging.info(f"Создано маппингов: {success_count}, Пропущено (существуют): {skip_count}, Ошибок: {error_count}")
        
        if error_count > 0:
            logging.warning(f"Синхронизация завершена с {error_count} ошибками. Проверьте логи.")
        else:
            logging.info("Синхронизация завершена УСПЕШНО!")
            
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        sys.exit(1)

# ------------------ ТОЧКА ВХОДА ------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Синхронизация прервана пользователем")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Необработанное исключение: {e}")
        sys.exit(1)
