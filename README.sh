#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import re
import os
import sys
import logging
from typing import List, Dict, Optional
from datetime import datetime
from dotenv import load_dotenv

# ------------------ НАСТРОЙКА ЛОГИРОВАНИЯ ------------------
LOG_FILE = "zabbix_ldap_sync.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
# Дублируем вывод в консоль для удобства
console = logging.StreamHandler()
console.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# ------------------ ЗАГРУЗКА ПЕРЕМЕННЫХ ------------------
load_dotenv("config.env")

# Проверка наличия всех обязательных переменных
REQUIRED_VARS = [
    "LDAP_URI", "LDAP_BASE", "LDAP_USER", "LDAP_PASS",
    "ZABBIX_URL", "ZABBIX_TOKEN", "LDAP_GROUP_PREFIX",
    "ROLE_VIEWER", "ROLE_EDITOR", "USER_DIRECTORY"
]
missing = [v for v in REQUIRED_VARS if not os.getenv(v)]
if missing:
    logging.error(f"Отсутствуют переменные: {', '.join(missing)}")
    sys.exit(1)

# --- Переменные из окружения ---
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

# Регулярное выражение для извлечения имени системы и типа группы из LDAP
REGEX = r"cr-gd-zabbix_csc_(csc-sys-[0-9]+)-(viewers|editors)"

# ------------------ КЛАСС ДЛЯ РАБОТЫ С ZABBIX API ------------------
class ZabbixAPI:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.id = 0
        self._verify_connection()

    def _call(self, method: str, params: dict, auth_required: bool = True) -> dict:
        """Универсальный метод для вызова API Zabbix."""
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
            raise Exception(f"Ошибка запроса к Zabbix: {e}")

        if "error" in data:
            err = data['error']
            raise Exception(f"Zabbix API error {err.get('code')}: {err.get('data', err.get('message'))}")
        if "result" not in data:
            raise Exception(f"Нет 'result' в ответе {method}: {data}")
        return data["result"]

    def _verify_connection(self):
        """Проверяет соединение с Zabbix API."""
        try:
            self._call("apiinfo.version", [], auth_required=False)
            logging.info("Соединение с Zabbix API установлено")
        except Exception as e:
            raise Exception(f"Не удалось подключиться к Zabbix: {e}")

    def get_roles(self) -> Dict[str, str]:
        """Возвращает словарь ролей Zabbix: имя -> roleid."""
        roles = self._call("role.get", {"output": ["roleid", "name"]})
        return {r["name"]: r["roleid"] for r in roles}

    def get_user_groups(self) -> Dict[str, str]:
        """Возвращает словарь групп пользователей Zabbix: имя -> usrgrpid."""
        groups = self._call("usergroup.get", {"output": ["usrgrpid", "name"]})
        return {g["name"]: g["usrgrpid"] for g in groups}

    def create_user_group(self, name: str) -> str:
        """Создаёт новую группу пользователей и возвращает её ID."""
        res = self._call("usergroup.create", {"name": name})
        return res["usrgrpids"][0]

    def get_user_directory(self, name: str) -> Optional[dict]:
        """Возвращает конфигурацию LDAP-каталога по имени."""
        directories = self._call("userdirectory.get", {
            "filter": {"name": name},
            "output": "extend",
            "selectProvisionGroups": "extend"
        })
        return directories[0] if directories else None

    def update_user_directory_provisioning(self, directory_id: str, provision_groups: List[dict]) -> dict:
        """Обновляет JIT-маппинги для LDAP-каталога."""
        return self._call("userdirectory.update", {
            "userdirectoryid": directory_id,
            "provision_groups": provision_groups
        })

# ------------------ РАБОТА С LDAP ------------------
def get_ldap_groups() -> List[dict]:
    """Получает список LDAP-групп, соответствующих заданному шаблону."""
    # Настройки LDAP-соединения
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
        raise Exception(f"Ошибка поиска в LDAP: {e}")
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
    logging.info(f"Найдено LDAP-групп, соответствующих шаблону: {len(groups)}")
    return groups

# ------------------ ОСНОВНАЯ ФУНКЦИЯ ------------------
def main():
    logging.info("=== НАЧАЛО СИНХРОНИЗАЦИИ LDAP -> ZABBIX ===")
    start = datetime.now()

    # 1. Подключение к Zabbix
    zbx = ZabbixAPI(ZABBIX_URL, ZABBIX_TOKEN)

    # 2. Получаем роли
    role_map = zbx.get_roles()
    if ROLE_VIEWER not in role_map:
        raise Exception(f"Роль '{ROLE_VIEWER}' не найдена. Доступные роли: {list(role_map.keys())}")
    if ROLE_EDITOR not in role_map:
        raise Exception(f"Роль '{ROLE_EDITOR}' не найдена. Доступные роли: {list(role_map.keys())}")
    logging.info(f"Найдены роли: {ROLE_VIEWER} (ID: {role_map[ROLE_VIEWER]}), {ROLE_EDITOR} (ID: {role_map[ROLE_EDITOR]})")

    # 3. Получаем LDAP-каталог
    directory = zbx.get_user_directory(USER_DIRECTORY)
    if not directory:
        raise Exception(f"LDAP-каталог '{USER_DIRECTORY}' не найден. Проверьте название.")
    directory_id = directory["userdirectoryid"]
    logging.info(f"Найден каталог '{USER_DIRECTORY}' (ID: {directory_id})")

    # 4. Получаем список групп из LDAP
    ldap_groups = get_ldap_groups()
    if not ldap_groups:
        logging.warning("Не найдено групп LDAP для синхронизации.")
        return

    # 5. Получаем существующие группы Zabbix
    existing_zabbix_groups = zbx.get_user_groups()

    # 6. Создаём недостающие группы Zabbix и готовим маппинг
    new_mappings = []
    created_groups = 0

    for lg in ldap_groups:
        # Имя группы в Zabbix (например, csc-sys-440-viewers)
        zabbix_group_name = f"{lg['system']}-{lg['type']}".lower()
        # Определяем роль
        role_name = ROLE_VIEWER if lg['type'] == 'viewers' else ROLE_EDITOR
        role_id = role_map[role_name]

        # Создаём группу в Zabbix, если её нет
        if zabbix_group_name not in existing_zabbix_groups:
            usrgrp_id = zbx.create_user_group(zabbix_group_name)
            existing_zabbix_groups[zabbix_group_name] = usrgrp_id
            created_groups += 1
            logging.info(f"Создана группа Zabbix: '{zabbix_group_name}' (ID: {usrgrp_id})")
        else:
            usrgrp_id = existing_zabbix_groups[zabbix_group_name]

        # Добавляем маппинг
        new_mappings.append({
            "name": lg["ldap_name"], # КОРРЕКТНОЕ имя параметра
            "roleid": role_id,
            "user_groups": [{"usrgrpid": usrgrp_id}]
        })

    # 7. Обновляем маппинги в LDAP-каталоге
    if new_mappings:
        # Если в каталоге уже есть маппинги, объединяем их с новыми
        existing_mappings = directory.get("provision_groups", [])
        merged_mappings = {m["name"]: m for m in existing_mappings}
        for m in new_mappings:
            merged_mappings[m["name"]] = m
        final_mappings = list(merged_mappings.values())

        zbx.update_user_directory_provisioning(directory_id, final_mappings)
        logging.info(f"Обновлены JIT-маппинги для каталога '{USER_DIRECTORY}': добавлено/обновлено {len(new_mappings)} записей.")
    else:
        logging.warning("Нет маппингов для обновления.")

    elapsed = datetime.now() - start
    logging.info(f"=== СИНХРОНИЗАЦИЯ ЗАВЕРШЕНА за {elapsed.total_seconds():.2f} с ===")
    logging.info(f"Создано групп в Zabbix: {created_groups}, настроено маппингов: {len(new_mappings)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Синхронизация прервана пользователем")
        sys.exit(0)
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        sys.exit(1)
