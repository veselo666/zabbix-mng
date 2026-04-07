#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import os
import sys
import logging
import re
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------ LOAD ENV ------------------
load_dotenv("config.env")

REQUIRED = [
    "LDAP_URI", "LDAP_BASE", "LDAP_USER", "LDAP_PASS",
    "ZABBIX_URL", "ZABBIX_TOKEN", "USER_DIRECTORY",
    "ROLE_DEFAULT", "ROLE_VIEWER", "ROLE_EDITOR",
    "SUPER_ADMIN_ROLE", "SUPER_ADMIN_GROUP"
]
missing = [v for v in REQUIRED if not os.getenv(v)]
if missing:
    print("Missing env:", missing)
    sys.exit(1)

# LDAP
LDAP_URI = os.getenv("LDAP_URI")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")
LDAP_TIMEOUT = int(os.getenv("LDAP_TIMEOUT", "10"))

# Zabbix
ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")
USER_DIRECTORY = os.getenv("USER_DIRECTORY")

ROLE_DEFAULT = os.getenv("ROLE_DEFAULT")
ROLE_VIEWER = os.getenv("ROLE_VIEWER")
ROLE_EDITOR = os.getenv("ROLE_EDITOR")
SUPER_ADMIN_ROLE = os.getenv("SUPER_ADMIN_ROLE")
SUPER_ADMIN_GROUP = os.getenv("SUPER_ADMIN_GROUP")

CSC_ROLE_VIEWER = os.getenv("CSC_ROLE_VIEWER")
CSC_ROLE_EDITOR = os.getenv("CSC_ROLE_EDITOR")
ATS_ROLE_VIEWER = os.getenv("ATS_ROLE_VIEWER")
ATS_ROLE_EDITOR = os.getenv("ATS_ROLE_EDITOR")
FCS_ROLE_VIEWER = os.getenv("FCS_ROLE_VIEWER")
FCS_ROLE_EDITOR = os.getenv("FCS_ROLE_EDITOR")
JET_ROLE_VIEWER = os.getenv("JET_ROLE_VIEWER")
JET_ROLE_EDITOR = os.getenv("JET_ROLE_EDITOR")

VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

# ------------------ LOGGING ------------------
LOG_DIR = "logs"
LOG_FILE = f"{LOG_DIR}/zabbix_ldap_sync.log"
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=5 * 1024 * 1024,
    backupCount=5
)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
console = logging.StreamHandler()
console.setFormatter(formatter)
logger.addHandler(console)

logging.info("===== START LDAP → ZABBIX SYNC =====")

# ------------------ REGEX ------------------
CSC_VIEWER_REGEX = r"cr-gd-zabbix[-_]?csc.*viewers$"
CSC_EDITOR_REGEX = r"cr-gd-zabbix[-_]?csc.*editors$"
ATS_VIEWER_REGEX = r"cr-gd-zabbix[-_]?ats.*viewers$"
ATS_EDITOR_REGEX = r"cr-gd-zabbix[-_]?ats.*editors$"
FCS_VIEWER_REGEX = r"cr-gd-zabbix[-_]?fcs.*viewers$"
FCS_EDITOR_REGEX = r"cr-gd-zabbix[-_]?fcs.*editors$"
JET_VIEWER_REGEX = r"cr-gd-zabbix[-_]?jet.*(viewers|app-users)$"
JET_EDITOR_REGEX = r"cr-gd-zabbix[-_]?jet.*(editors|app-admins)$"

# ------------------ ZABBIX API ------------------
def create_session():
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["POST"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

class ZabbixAPI:
    def __init__(self):
        self.session = create_session()
        self.id = 0

    def call(self, method, params):
        self.id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.id
        }
        headers = {
            "Content-Type": "application/json-rpc",
            "Authorization": f"Bearer {ZABBIX_TOKEN}"
        }
        r = self.session.post(ZABBIX_URL, json=payload, headers=headers, verify=VERIFY_SSL, timeout=30)
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise Exception(data["error"])
        return data["result"]

    def get_roles(self):
        roles = self.call("role.get", {"output": ["roleid","name"]})
        return {r["name"]: r["roleid"] for r in roles}

    def get_groups(self):
        groups = self.call("usergroup.get", {"output": ["usrgrpid","name"]})
        return {g["name"]: g["usrgrpid"] for g in groups}

    def get_media_types(self):
        mts = self.call("mediatype.get", {"output": ["mediatypeid","description"]})
        return {m["description"]: m["mediatypeid"] for m in mts}

    def get_directories(self):
        return self.call("userdirectory.get", {"output": "extend"})

    def update_directory(self, directory_id, payload):
        if DRY_RUN:
            logging.info("DRY RUN userdirectory.update")
            return
        self.call("userdirectory.update", {"userdirectoryid": directory_id, **payload})

# ------------------ LDAP ------------------
def get_ldap_groups():
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, LDAP_TIMEOUT)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    conn = ldap.initialize(LDAP_URI)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

    logging.info("LDAP connect")
    conn.simple_bind_s(LDAP_USER, LDAP_PASS)
    logging.info("LDAP bind OK")

    result = conn.search_s(
        LDAP_BASE,
        ldap.SCOPE_SUBTREE,
        "(cn=cr-gd-zabbix*)",
        ["cn"]
    )
    conn.unbind()

    groups = []
    for dn, entry in result:
        if "cn" not in entry:
            continue
        cn = entry["cn"][0].decode().strip()
        groups.append(cn)

    if not groups:
        raise Exception("LDAP returned zero groups")
    logging.info(f"LDAP groups found: {len(groups)}")
    return groups

# ------------------ ROLE DETECTION ------------------
def detect_role(name):
    n = name.lower()
    if n == SUPER_ADMIN_GROUP.lower():
        return SUPER_ADMIN_ROLE
    if re.search(CSC_EDITOR_REGEX, n): return CSC_ROLE_EDITOR
    if re.search(CSC_VIEWER_REGEX, n): return CSC_ROLE_VIEWER
    if re.search(ATS_EDITOR_REGEX, n): return ATS_ROLE_EDITOR
    if re.search(ATS_VIEWER_REGEX, n): return ATS_ROLE_VIEWER
    if re.search(FCS_EDITOR_REGEX, n): return FCS_ROLE_EDITOR
    if re.search(FCS_VIEWER_REGEX, n): return FCS_ROLE_VIEWER
    if re.search(JET_EDITOR_REGEX, n): return JET_ROLE_EDITOR
    if re.search(JET_VIEWER_REGEX, n): return JET_ROLE_VIEWER
    if "editors" in n: return ROLE_EDITOR
    if "viewers" in n: return ROLE_VIEWER
    return ROLE_DEFAULT

def normalize_group(name):
    n = name.lower()
    n = n.replace("cr-gd-", "").replace("zabbix_", "").replace("zabbix", "").replace("__","_")
    return n.strip("_")

def build_email(ldap_group):
    g = ldap_group.lower().replace("zabbix","").replace("__","_").strip("-_")
    match = re.match(r"cr[-_]gd[-_]?(.*?)-sys-(\d+)", g)
    if match:
        svc = match.group(1).upper()
        num = match.group(2)
        return f"cr-gd-{svc}-sys-{num}-notifications@company.com"
    return f"{g}-notifications@company.com"

# ------------------ MAIN ------------------
def main():
    zbx = ZabbixAPI()

    logging.info("Loading roles...")
    roles = zbx.get_roles()

    required_roles = [
        ROLE_DEFAULT,
        ROLE_VIEWER,
        ROLE_EDITOR,
        SUPER_ADMIN_ROLE,
        CSC_ROLE_VIEWER,
        CSC_ROLE_EDITOR,
        ATS_ROLE_VIEWER,
        ATS_ROLE_EDITOR,
        FCS_ROLE_VIEWER,
        FCS_ROLE_EDITOR,
        JET_ROLE_VIEWER,
        JET_ROLE_EDITOR
    ]
    for r in required_roles:
        if r and r not in roles:
            raise Exception(f"Role not found: {r}")

    directories = zbx.get_directories()
    directory = next((d for d in directories if d["name"] == USER_DIRECTORY), None)
    if not directory:
        raise Exception("User directory not found")

    directory_id = directory["userdirectoryid"]

    logging.info(f"Directory ID: {directory_id}")

    zabbix_groups = zbx.get_groups()
    ldap_groups = get_ldap_groups()

    # media types
    media_types = zbx.get_media_types()
    email_media_id = None
    for desc, mid in media_types.items():
        if "email" in desc.lower():
            email_media_id = mid
            break
    if not email_media_id:
        raise Exception(f"Email media type not found: {list(media_types.keys())}")

    # existing provisioning
    existing_groups = {m["name"]: m for m in directory.get("provision_groups", [])}
    existing_media = {(m["mediatypeid"], m["attribute"]) for m in directory.get("provision_media", [])}

    provision_groups = []
    provision_media = []

    for lg in ldap_groups:
        zname = normalize_group(lg)
        role_name = detect_role(lg)
        role_id = roles[role_name]

        if zname not in zabbix_groups:
            new_id = zbx.call("usergroup.create", {"name": zname})["usrgrpids"][0]
            zabbix_groups[zname] = new_id

        usrgrpid = zabbix_groups[zname]

        # idempotent groups
        if lg not in existing_groups:
            provision_groups.append({
                "name": lg,
                "roleid": role_id,
                "user_groups":[{"usrgrpid": usrgrpid}]
            })
        else:
            logging.info(f"Group {lg} already exists, skipping")

        email = build_email(lg)
        # idempotent media
        if (email_media_id, email) not in existing_media:
            provision_media.append({
                "name": lg,
                "mediatypeid": email_media_id,
                "attribute": email
            })
        else:
            logging.info(f"Email {email} already exists, skipping")

    payload = {
        "provision_groups": provision_groups,
        "provision_media": provision_media
    }

    zbx.update_directory(directory_id, payload)

    logging.info("Provision updated successfully")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"CRITICAL: {e}")
        sys.exit(1)
