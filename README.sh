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

REGEX = r"<<>>"

# ------------------ ZABBIX API ------------------
class ZabbixAPI:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.id = 0
        self._verify_connection()

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

    def _verify_connection(self):
        try:
            self._call("apiinfo.version", [], auth_required=False)
            logging.info("Соединение с Zabbix API установлено")
        except Exception as e:
            raise Exception(f"Не удалось подключиться к Zabbix: {e}")

    def get_roles(self) -> Dict[str, str]:
        roles = self._call("role.get", {"output": ["roleid", "name"]})
        return {r["name"]: r["roleid"] for r in roles}

    def get_user_group(self, name: str) -> Optional[dict]:
        # В Zabbix 7.4 usergroup.get принимает параметр name напрямую
        groups = self._call("usergroup.get", {"name": name})
        return groups[0] if groups else None

    def create_user_group(self, name: str) -> str:
        res = self._call("usergroup.create", {"name": name})
        return res["usrgrpids"][0]

    def get_user_directory(self, name: str) -> Optional[dict]:
        # userdirectory.get принимает параметр name напрямую
        directories = self._call("userdirectory.get", {"name": name, "output": "extend"})
        return directories[0] if directories else None

    def update_user_directory_mappings(self, directory_id: str, mappings: List[dict]) -> dict:
        return self._call("userdirectory.update", {
            "userdirectoryid": directory_id,
            "provisioning_group_mappings": mappings
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

    # Роли
    role_map = zbx.get_roles()
    if ROLE_VIEWER not in role_map:
        raise Exception(f"Роль '{ROLE_VIEWER}' не найдена")
    if ROLE_EDITOR not in role_map:
        raise Exception(f"Роль '{ROLE_EDITOR}' не найдена")

    # LDAP каталог
    directory = zbx.get_user_directory(USER_DIRECTORY)
    if not directory:
        raise Exception(f"Каталог '{USER_DIRECTORY}' не найден в Zabbix")
    dir_id = directory["userdirectoryid"]
    logging.info(f"Каталог '{USER_DIRECTORY}' ID={dir_id}")

    # Группы из LDAP
    ldap_groups = get_ldap_groups()
    if not ldap_groups:
        logging.warning("Нет групп LDAP для синхронизации")
        return

    # Создаём группы Zabbix и готовим маппинги
    new_mappings = []
    created = 0
    for lg in ldap_groups:
        group_name = f"{lg['system']}-{lg['type']}".lower()
        role_name = ROLE_VIEWER if lg['type'] == 'viewers' else ROLE_EDITOR
        role_id = role_map[role_name]

        ug = zbx.get_user_group(group_name)
        if ug:
            usrgrp_id = ug["usrgrpid"]
        else:
            usrgrp_id = zbx.create_user_group(group_name)
            created += 1
            logging.info(f"Создана группа '{group_name}'")

        new_mappings.append({
            "group_name": lg["ldap_name"],
            "usrgrps": [{"usrgrpid": usrgrp_id}],
            "roleid": role_id
        })

    # Объединяем с существующими маппингами
    existing = directory.get("provisioning_group_mappings", [])
    merged = {m["group_name"]: m for m in existing}
    for m in new_mappings:
        merged[m["group_name"]] = m
    final_mappings = list(merged.values())

    if final_mappings:
        zbx.update_user_directory_mappings(dir_id, final_mappings)
        logging.info(f"Обновлено маппингов: {len(final_mappings)}")
    else:
        logging.warning("Нет маппингов для обновления")

    elapsed = datetime.now() - start
    logging.info(f"=== Синхронизация завершена за {elapsed.total_seconds():.2f} с ===")
    logging.info(f"Создано групп Zabbix: {created}, маппингов: {len(new_mappings)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Прервано")
        sys.exit(0)
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        sys.exit(1)
