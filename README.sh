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
console = logging.StreamHandler()
console.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# ------------------ ЗАГРУЗКА ПЕРЕМЕННЫХ ------------------
load_dotenv("config.env")

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

REGEX = r"cr-gd-zabbix_csc_(csc-sys-[0-9]+)-(viewers|editors)"

# ------------------ ZABBIX API ------------------
class ZabbixAPI:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.id = 0

    def _call(self, method: str, params: dict, auth_required: bool = True) -> dict:
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

    def get_roles(self) -> Dict[str, str]:
        roles = self._call("role.get", {"output": ["roleid", "name"]})
        return {r["name"]: r["roleid"] for r in roles}

    def get_all_user_groups(self) -> List[dict]:
        return self._call("usergroup.get", {"output": ["usrgrpid", "name"]})

    def create_user_group(self, name: str) -> str:
        res = self._call("usergroup.create", {"name": name})
        return res["usrgrpids"][0]

    def get_all_user_directories(self) -> List[dict]:
        """Возвращает список всех LDAP-каталогов."""
        return self._call("userdirectory.get", {"output": "extend"})

    def update_user_directory_mappings(self, directory_id: str, mappings: List[dict]) -> dict:
        return self._call("userdirectory.update", {
            "userdirectoryid": directory_id,
            "provision_groups": mappings
        })

# ------------------ LDAP ------------------
def get_ldap_groups() -> List[dict]:
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    try:
        conn = ldap.initialize(LDAP_URI)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        conn.simple_bind_s(LDAP_USER, LDAP_PASS)
        logging.info(f"Подключено к LDAP: {LDAP_URI}")
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка LDAP: {e}")

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
        m = re.match(REGEX, cn)
        if m:
            groups.append({
                "ldap_name": cn,
                "system": m.group(1),
                "type": m.group(2)
            })
    logging.info(f"Найдено LDAP-групп: {len(groups)}")
    return groups

# ------------------ MAIN ------------------
def main():
    logging.info("=== НАЧАЛО СИНХРОНИЗАЦИИ ===")
    start = datetime.now()

    zbx = ZabbixAPI(ZABBIX_URL, ZABBIX_TOKEN)

    # 1. Получаем роли
    role_map = zbx.get_roles()
    if ROLE_VIEWER not in role_map:
        raise Exception(f"Роль '{ROLE_VIEWER}' не найдена. Доступные: {list(role_map.keys())}")
    if ROLE_EDITOR not in role_map:
        raise Exception(f"Роль '{ROLE_EDITOR}' не найдена. Доступные: {list(role_map.keys())}")

    # 2. Получаем все LDAP-каталоги и ищем нужный по имени
    directories = zbx.get_all_user_directories()
    directory = next((d for d in directories if d["name"] == USER_DIRECTORY), None)
    if not directory:
        raise Exception(f"Каталог '{USER_DIRECTORY}' не найден. Создайте его в Zabbix вручную.")
    dir_id = directory["userdirectoryid"]
    logging.info(f"Найден каталог '{USER_DIRECTORY}' ID={dir_id}")

    # 3. Получаем все группы пользователей Zabbix
    all_groups = zbx.get_all_user_groups()
    group_by_name = {g["name"]: g for g in all_groups}

    # 4. Получаем LDAP-группы
    ldap_groups = get_ldap_groups()
    if not ldap_groups:
        logging.warning("Нет LDAP-групп для синхронизации")
        return

    # 5. Создаём недостающие группы Zabbix и готовим маппинги
    new_mappings = []
    created_count = 0
    for lg in ldap_groups:
        zabbix_group_name = f"{lg['system']}-{lg['type']}".lower()
        role_name = ROLE_VIEWER if lg['type'] == 'viewers' else ROLE_EDITOR
        role_id = role_map[role_name]

        if zabbix_group_name in group_by_name:
            usrgrp_id = group_by_name[zabbix_group_name]["usrgrpid"]
        else:
            usrgrp_id = zbx.create_user_group(zabbix_group_name)
            created_count += 1
            logging.info(f"Создана группа Zabbix: '{zabbix_group_name}'")
            group_by_name[zabbix_group_name] = {"usrgrpid": usrgrp_id}

        new_mappings.append({
            "name": lg["ldap_name"],
            "roleid": role_id,
            "user_groups": [{"usrgrpid": usrgrp_id}]
        })

    # 6. Объединяем новые маппинги с существующими (чтобы не потерять ручные)
    existing_mappings = directory.get("provision_groups", [])
    merged = {m["name"]: m for m in existing_mappings}
    for m in new_mappings:
        merged[m["name"]] = m
    final_mappings = list(merged.values())

    if final_mappings:
        zbx.update_user_directory_mappings(dir_id, final_mappings)
        logging.info(f"Обновлены маппинги для каталога '{USER_DIRECTORY}': {len(final_mappings)} записей")
    else:
        logging.warning("Нет маппингов для обновления")

    elapsed = datetime.now() - start
    logging.info(f"=== СИНХРОНИЗАЦИЯ ЗАВЕРШЕНА за {elapsed.total_seconds():.2f} с ===")
    logging.info(f"Создано групп Zabbix: {created_count}, добавлено/обновлено маппингов: {len(new_mappings)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Прервано пользователем")
        sys.exit(0)
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        sys.exit(1)
