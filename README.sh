#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Синхронизация LDAP-групп с Zabbix 7.4 (и выше) через JIT-провижининг.
Создаёт группы пользователей в Zabbix и настраивает маппинг LDAP-групп на эти группы.
При первом входе пользователя Zabbix автоматически создаёт учётную запись с нужной ролью.
"""

import ldap
import requests
import re
import os
import sys
import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

# ------------------ НАСТРОЙКА ЛОГИРОВАНИЯ ------------------
LOG_FILE = "zabbix_ldap_sync.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
# Дублируем ошибки в консоль
console = logging.StreamHandler()
console.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# ------------------ ЗАГРУЗКА ПЕРЕМЕННЫХ ------------------
try:
    from dotenv import load_dotenv
    load_dotenv("config.env")
except ImportError:
    logging.warning("python-dotenv не установлен, используются системные переменные окружения")

REQUIRED_VARS = [
    "LDAP_URI", "LDAP_BASE", "LDAP_USER", "LDAP_PASS",
    "ZABBIX_URL", "ZABBIX_TOKEN", "LDAP_GROUP_PREFIX",
    "ROLE_VIEWER", "ROLE_EDITOR", "USER_DIRECTORY"
]
missing = [v for v in REQUIRED_VARS if not os.getenv(v)]
if missing:
    logging.error(f"Отсутствуют переменные: {', '.join(missing)}")
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

# Регулярное выражение для извлечения system и type из имени LDAP-группы
# Пример: 
REGEX = r"<<>>"

# ------------------ КЛАСС ДЛЯ РАБОТЫ С ZABBIX API ------------------
class ZabbixAPI:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.id = 0
        self._verify_connection()

    def _call(self, method: str, params: Any, auth_required: bool = True) -> Any:
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
            resp = requests.post(self.url, json=payload, headers=headers, verify=False, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise Exception(f"HTTP/JSON ошибка при вызове {method}: {e}")

        if "error" in data:
            err = data['error']
            raise Exception(f"Zabbix API error {err.get('code')}: {err.get('data', err.get('message'))}")
        if "result" not in data:
            raise Exception(f"Метод {method} не вернул 'result': {data}")
        return data["result"]

    def _verify_connection(self):
        """Проверка доступности API (без авторизации)."""
        try:
            version = self._call("apiinfo.version", [], auth_required=False)
            logging.info(f"Подключено к Zabbix API, версия: {version}")
        except Exception as e:
            logging.error(f"Не удалось подключиться к Zabbix API: {e}")
            raise

    def get_roles(self) -> Dict[str, str]:
        """Возвращает {имя_роли: roleid}."""
        roles = self._call("role.get", {"output": ["roleid", "name"]})
        return {r["name"]: r["roleid"] for r in roles}

    def get_user_group(self, name: str) -> Optional[Dict]:
        """Возвращает группу пользователей по имени."""
        groups = self._call("usergroup.get", {"filter": {"name": name}})
        return groups[0] if groups else None

    def create_user_group(self, name: str) -> str:
        """Создаёт группу пользователей и возвращает её ID."""
        result = self._call("usergroup.create", {"name": name})
        return result["usrgrpids"][0]

    def get_user_directory(self, name: str) -> Optional[Dict]:
        """Возвращает LDAP-каталог по имени."""
        directories = self._call("userdirectory.get", {"filter": {"name": name}, "output": "extend"})
        return directories[0] if directories else None

    def update_user_directory_mappings(self, directory_id: str, mappings: List[Dict]) -> Dict:
        """Обновляет маппинги LDAP-групп в каталоге."""
        return self._call("userdirectory.update", {
            "userdirectoryid": directory_id,
            "provisioning_group_mappings": mappings
        })

# ------------------ РАБОТА С LDAP ------------------
def get_ldap_groups() -> List[Dict[str, str]]:
    """Возвращает список LDAP-групп, соответствующих шаблону."""
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    try:
        conn = ldap.initialize(LDAP_URI)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        conn.simple_bind_s(LDAP_USER, LDAP_PASS)
        logging.info(f"Подключено к LDAP: {LDAP_URI}")
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка подключения к LDAP: {e}")

    try:
        search_filter = f"(cn={PREFIX}*)"
        result = conn.search_s(LDAP_BASE, ldap.SCOPE_SUBTREE, search_filter, ["cn"])
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка поиска LDAP: {e}")
    finally:
        conn.unbind()

    groups = []
    for dn, entry in result:
        if not entry or "cn" not in entry:
            continue
        cn_raw = entry["cn"][0]
        cn = cn_raw.decode("utf-8") if isinstance(cn_raw, bytes) else cn_raw
        match = re.match(REGEX, cn)
        if match:
            groups.append({
                "ldap_name": cn,
                "system": match.group(1),
                "type": match.group(2)
            })
    logging.info(f"Найдено LDAP-групп: {len(groups)}")
    return groups

# ------------------ ОСНОВНАЯ ЛОГИКА ------------------
def main():
    logging.info("=== НАЧАЛО СИНХРОНИЗАЦИИ LDAP -> ZABBIX ===")
    start = datetime.now()

    # 1. Подключение к Zabbix
    zbx = ZabbixAPI(ZABBIX_URL, ZABBIX_TOKEN)

    # 2. Получение ролей
    role_map = zbx.get_roles()
    if ROLE_VIEWER not in role_map:
        raise Exception(f"Роль '{ROLE_VIEWER}' не найдена. Доступные: {list(role_map.keys())}")
    if ROLE_EDITOR not in role_map:
        raise Exception(f"Роль '{ROLE_EDITOR}' не найдена. Доступные: {list(role_map.keys())}")

    # 3. Получение LDAP-каталога
    directory = zbx.get_user_directory(USER_DIRECTORY)
    if not directory:
        raise Exception(f"LDAP-каталог '{USER_DIRECTORY}' не найден. Создайте его в Zabbix вручную.")
    directory_id = directory["userdirectoryid"]
    logging.info(f"LDAP-каталог: {USER_DIRECTORY} (ID={directory_id})")

    # 4. Получение групп из LDAP
    ldap_groups = get_ldap_groups()
    if not ldap_groups:
        logging.warning("Не найдено групп LDAP. Проверьте префикс и регулярное выражение.")
        return

    # 5. Создание групп пользователей Zabbix и подготовка маппингов
    new_mappings = []
    created_groups = 0
    for lg in ldap_groups:
        system = lg["system"]
        gtype = lg["type"]
        user_group_name = f"{system}-{gtype}".lower()
        role_name = ROLE_VIEWER if gtype == "viewers" else ROLE_EDITOR
        role_id = role_map[role_name]

        # Создаём группу пользователей, если её нет
        ug = zbx.get_user_group(user_group_name)
        if ug:
            usrgrp_id = ug["usrgrpid"]
        else:
            usrgrp_id = zbx.create_user_group(user_group_name)
            created_groups += 1
            logging.info(f"Создана группа пользователей: {user_group_name}")

        # Добавляем маппинг
        new_mappings.append({
            "group_name": lg["ldap_name"],
            "usrgrps": [{"usrgrpid": usrgrp_id}],
            "roleid": role_id
        })

    # 6. Получение существующих маппингов из каталога (чтобы не потерять их)
    existing_mappings = directory.get("provisioning_group_mappings", [])
    # Объединяем: старые + новые (по уникальности group_name)
    existing_map = {m["group_name"]: m for m in existing_mappings}
    for m in new_mappings:
        existing_map[m["group_name"]] = m
    final_mappings = list(existing_map.values())

    # 7. Обновление каталога
    if final_mappings:
        zbx.update_user_directory_mappings(directory_id, final_mappings)
        logging.info(f"Обновлены маппинги: {len(final_mappings)} записей")
    else:
        logging.warning("Нет маппингов для обновления")

    # Итог
    elapsed = datetime.now() - start
    logging.info(f"=== СИНХРОНИЗАЦИЯ ЗАВЕРШЕНА за {elapsed.total_seconds():.2f} с ===")
    logging.info(f"Создано групп Zabbix: {created_groups}, маппингов: {len(new_mappings)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Прервано пользователем")
        sys.exit(0)
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        sys.exit(1)
