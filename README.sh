#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import os
import sys
import logging
from datetime import datetime
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re

# ------------------ LOAD ENV ------------------
load_dotenv("config.env")

REQUIRED = [
    "LDAP_URI", "LDAP_BASE", "LDAP_USER", "LDAP_PASS",
    "ZABBIX_URL", "ZABBIX_TOKEN", "USER_DIRECTORY",
    "ROLE_VIEWER", "ROLE_EDITOR", "ROLE_DEFAULT",
    "SUPER_ADMIN_ROLE", "SUPER_ADMIN_GROUP"
]

missing = [v for v in REQUIRED if not os.getenv(v)]
if missing:
    print("Missing env:", missing)
    sys.exit(1)

LDAP_URI = os.getenv("LDAP_URI")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")
LDAP_TIMEOUT = int(os.getenv("LDAP_TIMEOUT", "10"))

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")
USER_DIRECTORY = os.getenv("USER_DIRECTORY")

ROLE_VIEWER = os.getenv("ROLE_VIEWER")
ROLE_EDITOR = os.getenv("ROLE_EDITOR")
ROLE_DEFAULT = os.getenv("ROLE_DEFAULT")
SUPER_ADMIN_ROLE = os.getenv("SUPER_ADMIN_ROLE")
SUPER_ADMIN_GROUP = os.getenv("SUPER_ADMIN_GROUP")

VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

# ------------------ LOGGING ------------------
log_file = f"logs/zabbix_ldap_sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# ------------------ HTTP SESSION ------------------
def create_session():
    session = requests.Session()
    retry = Retry(total=5, backoff_factor=1, status_forcelist=[500,502,503,504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# ------------------ ZABBIX API ------------------
class ZabbixAPI:
    def __init__(self):
        self.session = create_session()
        self.id = 0

    def call(self, method, params):
        self.id += 1
        payload = {"jsonrpc":"2.0","method":method,"params":params,"id":self.id}
        headers = {"Content-Type":"application/json-rpc","Authorization": f"Bearer {ZABBIX_TOKEN}"}
        r = self.session.post(ZABBIX_URL, json=payload, headers=headers, verify=VERIFY_SSL, timeout=30)
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise Exception(data["error"])
        return data["result"]

    def get_roles(self):
        roles = self.call("role.get", {"output": ["roleid", "name"]})
        return {r["name"]: r["roleid"] for r in roles}

    def get_groups(self):
        groups = self.call("usergroup.get", {"output": ["usrgrpid", "name"]})
        return {g["name"]: g["usrgrpid"] for g in groups}

    def create_group(self, name):
        if DRY_RUN:
            logging.info(f"DRY RUN create group {name}")
            return "0"
        res = self.call("usergroup.create", {"name": name})
        return res["usrgrpids"][0]

    def get_directories(self):
        return self.call("userdirectory.get", {"output": "extend"})

    def update_provision(self, directory_id, mappings):
        if DRY_RUN:
            logging.info("DRY RUN provisioning update")
            return
        self.call("userdirectory.update", {"userdirectoryid": directory_id, "provision_groups": mappings})

# ------------------ LDAP ------------------
def get_ldap_groups():
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, LDAP_TIMEOUT)
    conn = ldap.initialize(LDAP_URI)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    logging.info("LDAP connect...")
    conn.simple_bind_s(LDAP_USER, LDAP_PASS)
    logging.info("LDAP bind OK")
    search_filter = "(cn=cr-gd-zabbix*)"
    result = conn.search_s(LDAP_BASE, ldap.SCOPE_SUBTREE, search_filter, ["cn"])
    conn.unbind()
    groups = []
    for dn, entry in result:
        if "cn" not in entry: continue
        cn = entry["cn"][0].decode().strip()
        if "zabbix" not in cn.lower(): continue
        groups.append(cn)
    logging.info(f"LDAP groups found: {len(groups)}")
    for g in groups:
        logging.info(f"LDAP: {g}")
    return groups

# ------------------ ROLE DETECTION ------------------
def detect_role(name):
    n = name.lower()
    if n == SUPER_ADMIN_GROUP.lower():
        return SUPER_ADMIN_ROLE
    if "csc" in n and "editors" in n:
        return os.getenv("CSC_ROLE_EDITOR")
    if "csc" in n and "viewers" in n:
        return os.getenv("CSC_ROLE_VIEWER")
    if "ats" in n and "editors" in n:
        return os.getenv("ATS_ROLE_EDITOR")
    if "ats" in n and "viewers" in n:
        return os.getenv("ATS_ROLE_VIEWER")
    if "fcs" in n and "editors" in n:
        return os.getenv("FCS_ROLE_EDITOR")
    if "fcs" in n and "viewers" in n:
        return os.getenv("FCS_ROLE_VIEWER")
    if "jet" in n and "editors" in n:
        return os.getenv("JET_ROLE_EDITOR")
    if "jet" in n and "viewers" in n:
        return os.getenv("JET_ROLE_VIEWER")
    if "editors" in n:
        return ROLE_EDITOR
    if "viewers" in n:
        return ROLE_VIEWER
    return ROLE_DEFAULT

# ------------------ NORMALIZE GROUP NAME ------------------
def normalize_group(name):
    n = name.lower()
    n = n.replace("cr-gd-", "").replace("zabbix_", "").replace("zabbix", "").replace("__","_").strip("_")
    return n

# ------------------ GENERATE EMAIL ------------------
def group_to_email(ldap_group):
    g = ldap_group.lower().replace("__","_").replace("zabbix","").strip("-_")
    match = re.match(r"cr[-_]gd[-_]?(.*?)-sys-(\d+)", g)
    if match:
        service = match.group(1).upper()
        num = match.group(2)
        email = f"cr-gd-{service}-sys-{num}-notifications@company.com"
        return email
    return f"{g}-notifications@company.com"

# ------------------ MAIN ------------------
def main():
    logging.info("===== START LDAP → ZABBIX SYNC =====")
    zbx = ZabbixAPI()
    roles = zbx.get_roles()
    for r in [ROLE_VIEWER, ROLE_EDITOR, ROLE_DEFAULT, SUPER_ADMIN_ROLE]:
        if r not in roles:
            raise Exception(f"Role not found: {r}")
    directories = zbx.get_directories()
    directory = next((d for d in directories if d["name"] == USER_DIRECTORY), None)
    if not directory:
        raise Exception("User directory not found")
    directory_id = directory["userdirectoryid"]
    logging.info(f"Directory ID: {directory_id}")
    zabbix_groups = zbx.get_groups()
    ldap_groups = get_ldap_groups()
    new_mappings = []
    for ldap_group in ldap_groups:
        zabbix_group = normalize_group(ldap_group)
        role_name = detect_role(ldap_group)
        role_id = roles[role_name]
        if zabbix_group not in zabbix_groups:
            usrgrpid = zbx.create_group(zabbix_group)
            zabbix_groups[zabbix_group] = usrgrpid
            logging.info(f"Created Zabbix group: {zabbix_group}")
        usrgrpid = zabbix_groups[zabbix_group]
        email_address = group_to_email(ldap_group)
        mapping = {
            "name": ldap_group,
            "roleid": role_id,
            "user_groups": [{"usrgrpid": usrgrpid}],
            "medias": [{"mediatype":"Email","sendto":email_address,"active":0,"severity":63,"period":"1-7,00:00-24:00"}]
        }
        new_mappings.append(mapping)
        logging.info(f"MAP: {ldap_group} → {zabbix_group} → {role_name} → {email_address}")
    existing = directory.get("provision_groups", [])
    merged = {m["name"]: m for m in existing}
    for m in new_mappings:
        merged[m["name"]] = m
    final = list(merged.values())
    zbx.update_provision(directory_id, final)
    logging.info(f"Provision updated: {len(final)} groups")
    logging.info("===== SYNC COMPLETED =====")

# ------------------ ENTRY ------------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"CRITICAL: {e}")
        sys.exit(1)
