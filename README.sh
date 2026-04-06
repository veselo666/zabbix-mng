#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import os
import sys
import logging
from typing import List, Dict
from datetime import datetime
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------ LOAD ENV ------------------

load_dotenv("config.env")

REQUIRED_VARS = [
    "LDAP_URI",
    "LDAP_BASE",
    "LDAP_USER",
    "LDAP_PASS",
    "LDAP_GROUP_PREFIX",
    "ZABBIX_URL",
    "ZABBIX_TOKEN",
    "USER_DIRECTORY",
    "ROLE_VIEWER",
    "ROLE_EDITOR",
    "ROLE_DEFAULT"
]

missing = [v for v in REQUIRED_VARS if not os.getenv(v)]
if missing:
    print(f"Missing env vars: {missing}")
    sys.exit(1)

LDAP_URI = os.getenv("LDAP_URI")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")
PREFIX = os.getenv("LDAP_GROUP_PREFIX")

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")

USER_DIRECTORY = os.getenv("USER_DIRECTORY")

ROLE_VIEWER = os.getenv("ROLE_VIEWER")
ROLE_EDITOR = os.getenv("ROLE_EDITOR")
ROLE_DEFAULT = os.getenv("ROLE_DEFAULT")

VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

# ------------------ LOGGING ------------------

logging.basicConfig(
    filename="zabbix_ldap_sync.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# ------------------ HTTP SESSION ------------------

def create_session():

    session = requests.Session()

    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504]
    )

    adapter = HTTPAdapter(max_retries=retry)

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session

# ------------------ ZABBIX API ------------------

class ZabbixAPI:

    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.id = 0
        self.session = create_session()

    def call(self, method: str, params: dict):

        self.id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.id
        }

        headers = {
            "Content-Type": "application/json-rpc",
            "Authorization": f"Bearer {self.token}"
        }

        response = self.session.post(
            self.url,
            json=payload,
            headers=headers,
            verify=VERIFY_SSL,
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        if "error" in data:
            raise Exception(data["error"])

        return data["result"]

    def get_roles(self):

        roles = self.call("role.get", {"output": ["roleid", "name"]})
        return {r["name"]: r["roleid"] for r in roles}

    def get_user_groups(self):

        groups = self.call("usergroup.get", {"output": ["usrgrpid", "name"]})
        return {g["name"]: g["usrgrpid"] for g in groups}

    def create_user_group(self, name):

        if DRY_RUN:
            logging.info(f"DRY RUN: create group {name}")
            return "0"

        res = self.call("usergroup.create", {"name": name})
        return res["usrgrpids"][0]

    def get_directories(self):

        return self.call("userdirectory.get", {"output": "extend"})

    def update_provisioning(self, directory_id, mappings):

        if DRY_RUN:
            logging.info("DRY RUN: provisioning update skipped")
            return

        self.call(
            "userdirectory.update",
            {
                "userdirectoryid": directory_id,
                "provision_groups": mappings
            }
        )

# ------------------ LDAP ------------------

def get_ldap_groups():

    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)

    if os.getenv("LDAP_IGNORE_CERT", "true").lower() == "true":
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    conn = ldap.initialize(LDAP_URI)

    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

    if LDAP_URI.startswith("ldaps://"):
        conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
        conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

    try:
        conn.simple_bind_s(LDAP_USER, LDAP_PASS)
        logging.info("LDAP bind successful")
    except ldap.LDAPError as e:
        raise Exception(f"LDAP bind error: {e}")

    search_filter = f"(cn={PREFIX}*)"

    result = conn.search_s(
        LDAP_BASE,
        ldap.SCOPE_SUBTREE,
        search_filter,
        ["cn"]
    )

    conn.unbind()

    groups = []

    for dn, entry in result:

        if "cn" not in entry:
            continue

        cn = entry["cn"][0].decode()

        if cn.startswith(PREFIX):
            groups.append(cn)

    logging.info(f"LDAP groups found: {len(groups)}")

    return groups

# ------------------ ROLE DETECTION ------------------

def detect_role(group_name: str):

    name = group_name.lower()

    if name.endswith("viewers"):
        return ROLE_VIEWER

    if name.endswith("editors"):
        return ROLE_EDITOR

    return ROLE_DEFAULT

# ------------------ MAIN ------------------

def main():

    logging.info("START LDAP → ZABBIX SYNC")

    zbx = ZabbixAPI(ZABBIX_URL, ZABBIX_TOKEN)

    roles = zbx.get_roles()

    for r in [ROLE_VIEWER, ROLE_EDITOR, ROLE_DEFAULT]:
        if r not in roles:
            raise Exception(f"Role {r} not found in Zabbix")

    directories = zbx.get_directories()

    directory = next(
        (d for d in directories if d["name"] == USER_DIRECTORY),
        None
    )

    if not directory:
        raise Exception("LDAP directory not found")

    directory_id = directory["userdirectoryid"]

    logging.info(f"Directory ID: {directory_id}")

    zabbix_groups = zbx.get_user_groups()

    ldap_groups = get_ldap_groups()

    new_mappings = []

    for ldap_group in ldap_groups:

        zabbix_group = ldap_group.replace(PREFIX, "").lower()

        role_name = detect_role(ldap_group)
        role_id = roles[role_name]

        if zabbix_group not in zabbix_groups:

            usrgrpid = zbx.create_user_group(zabbix_group)

            zabbix_groups[zabbix_group] = usrgrpid

            logging.info(f"Created group: {zabbix_group}")

        usrgrpid = zabbix_groups[zabbix_group]

        new_mappings.append({
            "name": ldap_group,
            "roleid": role_id,
            "user_groups": [
                {"usrgrpid": usrgrpid}
            ]
        })

    existing = directory.get("provision_groups", [])

    merged = {m["name"]: m for m in existing}

    for m in new_mappings:
        merged[m["name"]] = m

    final = list(merged.values())

    zbx.update_provisioning(directory_id, final)

    logging.info(f"Provisioning updated: {len(final)} groups")

    logging.info("SYNC COMPLETED")

# ------------------ ENTRY ------------------

if __name__ == "__main__":

    try:
        main()

    except Exception as e:

        logging.error(f"CRITICAL: {e}")

        sys.exit(1)
