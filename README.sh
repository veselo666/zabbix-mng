#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import re
import os
import sys
import logging
from typing import List, Dict
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

REQUIRED = [
    "LDAP_URI",
    "LDAP_BASE",
    "LDAP_USER",
    "LDAP_PASS",
    "ZABBIX_URL",
    "ZABBIX_TOKEN",
    "USER_DIRECTORY",

    "SUPER_ADMIN_ROLE",
    "SUPER_ADMIN_GROUP",

    "ROLE_DEFAULT",

    "CSC_ROLE_VIEWER",
    "CSC_ROLE_EDITOR",

    "ATS_ROLE_VIEWER",
    "ATS_ROLE_EDITOR",

    "FCS_ROLE_VIEWER",
    "FCS_ROLE_EDITOR",

    "JET_ROLE_VIEWER",
    "JET_ROLE_EDITOR"
]

missing = [v for v in REQUIRED if not os.getenv(v)]
if missing:
    logging.error(f"Отсутствуют переменные: {', '.join(missing)}")
    sys.exit(1)

LDAP_URI = os.getenv("LDAP_URI")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")

LDAP_GROUP_BASE = os.getenv("LDAP_GROUP_BASE", LDAP_BASE)
LDAP_FILTER = os.getenv("LDAP_FILTER", "(objectClass=group)")
LDAP_IGNORE_CERT = os.getenv("LDAP_IGNORE_CERT", "true").lower() == "true"

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")
USER_DIRECTORY = os.getenv("USER_DIRECTORY")

SUPER_ADMIN_ROLE = os.getenv("SUPER_ADMIN_ROLE")
SUPER_ADMIN_GROUP = os.getenv("SUPER_ADMIN_GROUP")

ROLE_DEFAULT = os.getenv("ROLE_DEFAULT")

CSC_ROLE_VIEWER = os.getenv("CSC_ROLE_VIEWER")
CSC_ROLE_EDITOR = os.getenv("CSC_ROLE_EDITOR")

ATS_ROLE_VIEWER = os.getenv("ATS_ROLE_VIEWER")
ATS_ROLE_EDITOR = os.getenv("ATS_ROLE_EDITOR")

FCS_ROLE_VIEWER = os.getenv("FCS_ROLE_VIEWER")
FCS_ROLE_EDITOR = os.getenv("FCS_ROLE_EDITOR")

JET_ROLE_VIEWER = os.getenv("JET_ROLE_VIEWER")
JET_ROLE_EDITOR = os.getenv("JET_ROLE_EDITOR")

DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"

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
            resp = requests.post(self.url, json=payload, headers=headers, verify=VERIFY_SSL, timeout=30)
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
        return self._call("userdirectory.get", {"output": "extend"})

    def update_user_directory_mappings(self, directory_id: str, mappings: List[dict]) -> dict:
        if DRY_RUN:
            logging.info(f"DRY_RUN: обновление {len(mappings)} маппингов пропущено")
            return {}
        return self._call("userdirectory.update", {
            "userdirectoryid": directory_id,
            "provision_groups": mappings
        })

# ------------------ LDAP ------------------
def get_ldap_groups() -> List[dict]:
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER if LDAP_IGNORE_CERT else ldap.OPT_X_TLS_DEMAND)

    try:
        conn = ldap.initialize(LDAP_URI)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        conn.simple_bind_s(LDAP_USER, LDAP_PASS)
        logging.info(f"Подключено к LDAP: {LDAP_URI}")
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка LDAP: {e}")

    try:
        result = conn.search_s(LDAP_GROUP_BASE, ldap.SCOPE_SUBTREE, LDAP_FILTER, ["cn"])
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
        groups.append(cn)
    logging.info(f"Найдено LDAP-групп: {len(groups)}")
    return groups

# ------------------ ROLE DETECTION ------------------
def detect_role(group_name: str) -> str:
    g = group_name.lower()
    if g == SUPER_ADMIN_GROUP.lower():
        return SUPER_ADMIN_ROLE
    if re.search(r"cr-gd-zabbix[-_]csc.*editors", g):
        return CSC_ROLE_EDITOR
    if re.search(r"cr-gd-zabbix[-_]csc.*viewers", g):
        return CSC_ROLE_VIEWER
    if re.search(r"cr-gd-zabbix[-_]ats.*editors", g):
        return ATS_ROLE_EDITOR
    if re.search(r"cr-gd-zabbix[-_]ats.*viewers", g):
        return ATS_ROLE_VIEWER
    if re.search(r"cr-gd-zabbix[-_]fcs.*editors", g):
        return FCS_ROLE_EDITOR
    if re.search(r"cr-gd-zabbix[-_]fcs.*viewers", g):
        return FCS_ROLE_VIEWER
    if re.search(r"cr-gd-zabbix[-_]jet.*(editors|app-admins)", g):
        return JET_ROLE_EDITOR
    if re.search(r"cr-gd-zabbix[-_]jet.*(viewers|app-users)", g):
        return JET_ROLE_VIEWER
    return ROLE_DEFAULT

# ------------------ MAIN ------------------
def main():
    logging.info("=== НАЧАЛО СИНХРОНИЗАЦИИ ===")
    start = datetime.now()

    zbx = ZabbixAPI(ZABBIX_URL, ZABBIX_TOKEN)

    # --- Роли ---
    roles = zbx.get_roles()
    required_roles = [
        SUPER_ADMIN_ROLE,
        CSC_ROLE_VIEWER, CSC_ROLE_EDITOR,
        ATS_ROLE_VIEWER, ATS_ROLE_EDITOR,
        FCS_ROLE_VIEWER, FCS_ROLE_EDITOR,
        JET_ROLE_VIEWER, JET_ROLE_EDITOR,
        ROLE_DEFAULT
    ]
    for r in required_roles:
        if r not in roles:
            raise Exception(f"Zabbix role not found: {r}")

    # --- LDAP-каталог ---
    directories = zbx.get_all_user_directories()
    directory = next((d for d in directories if d["name"] == USER_DIRECTORY), None)
    if not directory:
        raise Exception(f"Каталог '{USER_DIRECTORY}' не найден. Создайте его в Zabbix вручную.")
    dir_id = directory["userdirectoryid"]
    logging.info(f"Найден каталог '{USER_DIRECTORY}' ID={dir_id}")

    # --- Группы Zabbix ---
    all_groups = zbx.get_all_user_groups()
    group_by_name = {g["name"]: g for g in all_groups}

    # --- LDAP-группы ---
    ldap_groups = get_ldap_groups()
    if not ldap_groups:
        logging.warning("Нет LDAP-групп для синхронизации")
        return

    # --- Создание и маппинг ---
    new_mappings = []
    created_count = 0
    for lg in ldap_groups:
        role_name = detect_role(lg)
        zabbix_group_name = lg.lower().replace("_", "-")
        if zabbix_group_name in group_by_name:
            usrgrp_id = group_by_name[zabbix_group_name]["usrgrpid"]
        else:
            if not DRY_RUN:
                usrgrp_id = zbx.create_user_group(zabbix_group_name)
                logging.info(f"Создана группа Zabbix: '{zabbix_group_name}'")
            else:
                usrgrp_id = f"DRY_{zabbix_group_name}"
                logging.info(f"DRY_RUN: Группа {zabbix_group_name} не создавалась")
            created_count += 1
            group_by_name[zabbix_group_name] = {"usrgrpid": usrgrp_id}

        new_mappings.append({
            "name": lg,
            "roleid": roles[role_name],
            "user_groups": [{"usrgrpid": usrgrp_id}]
        })
        logging.info(f"MAP: {lg} → {zabbix_group_name} → {role_name}")

    # --- Объединение с существующими ---
    existing_mappings = directory.get("provision_groups", [])
    merged = {m["name"]: m for m in existing_mappings}
    for m in new_mappings:
        merged[m["name"]] = m
    final_mappings = list(merged.values())

    # --- Обновление Zabbix ---
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












        LDAP_URI=ldaps://10.10.10.10:636
LDAP_BASE=DC=domain,DC=local
LDAP_USER=CN=zabbix,OU=Service,DC=domain,DC=local
LDAP_PASS=secret

LDAP_IGNORE_CERT=true

ZABBIX_URL=https://zabbix.domain.local/api_jsonrpc.php
ZABBIX_TOKEN=xxxxxxxx

USER_DIRECTORY=LDAP

# --- SUPER ADMIN ---
SUPER_ADMIN_ROLE=CSC Super Admin
SUPER_ADMIN_GROUP=cr-gd-zabbix_csc_zabbixfcs-superadmin

# --- DEFAULT ---
ROLE_DEFAULT=Viewer

# --- CSC ---
CSC_ROLE_VIEWER=CSC Viewer
CSC_ROLE_EDITOR=CSC Editor

# --- ATS ---
ATS_ROLE_VIEWER=ATS Viewer
ATS_ROLE_EDITOR=ATS Editor

# --- FCS ---
FCS_ROLE_VIEWER=FCS Viewer
FCS_ROLE_EDITOR=FCS Editor

# --- JET ---
JET_ROLE_VIEWER=JET Viewer
JET_ROLE_EDITOR=JET Editor

VERIFY_SSL=false
DRY_RUN=false
