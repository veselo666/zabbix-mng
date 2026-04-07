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

# =========================================================
# LOAD ENV
# =========================================================

ENV_FILE = "config.env"

if not os.path.exists(ENV_FILE):
    print("config.env not found")
    sys.exit(1)

load_dotenv(ENV_FILE)

REQUIRED = [
    # LDAP
    "LDAP_URI",
    "LDAP_BASE",
    "LDAP_USER",
    "LDAP_PASS",

    # Zabbix
    "ZABBIX_URL",
    "ZABBIX_TOKEN",
    "USER_DIRECTORY",

    # Default roles
    "ROLE_DEFAULT",
    "ROLE_VIEWER",
    "ROLE_EDITOR",

    # Super Admin
    "SUPER_ADMIN_ROLE",
    "SUPER_ADMIN_GROUP",

    # CSC
    "CSC_ROLE_VIEWER",
    "CSC_ROLE_EDITOR",

    # ATS
    "ATS_ROLE_VIEWER",
    "ATS_ROLE_EDITOR",

    # FCS
    "FCS_ROLE_VIEWER",
    "FCS_ROLE_EDITOR",

    # JET
    "JET_ROLE_VIEWER",
    "JET_ROLE_EDITOR",

    # Media Types
    "MEDIA_TYPE_EMAIL",
    "LDAP_EMAIL_ATTR",
]

missing = [v for v in REQUIRED if not os.getenv(v)]

if missing:
    print("Missing env variables:")
    for m in missing:
        print(m)
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
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

# Roles
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

# Media Types
MEDIA_TYPE_EMAIL = os.getenv("MEDIA_TYPE_EMAIL")
LDAP_EMAIL_ATTR = os.getenv("LDAP_EMAIL_ATTR")

# Media mapping regex
CSC_MEDIA_EMAIL = os.getenv("CSC_MEDIA_EMAIL", r"cr-gd-zabbix[-_]?csc.*")
ATS_MEDIA_EMAIL = os.getenv("ATS_MEDIA_EMAIL", r"cr-gd-zabbix[-_]?ats.*")
FCS_MEDIA_EMAIL = os.getenv("FCS_MEDIA_EMAIL", r"cr-gd-zabbix[-_]?fcs.*")
JET_MEDIA_EMAIL = os.getenv("JET_MEDIA_EMAIL", r"cr-gd-zabbix[-_]?jet.*")
DEFAULT_MEDIA_TYPE = os.getenv("DEFAULT_MEDIA_TYPE", MEDIA_TYPE_EMAIL)

# =========================================================
# LOGGING
# =========================================================

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

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
)

file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console = logging.StreamHandler()
console.setFormatter(formatter)
logger.addHandler(console)

logging.info("=====================================")
logging.info("LDAP → ZABBIX SYNC START")
logging.info("=====================================")

# =========================================================
# REGEX
# =========================================================

CSC_VIEWER_REGEX = r"cr-gd-zabbix[-_]?csc.*viewers$"
CSC_EDITOR_REGEX = r"cr-gd-zabbix[-_]?csc.*editors$"

ATS_VIEWER_REGEX = r"cr-gd-zabbix[-_]?ats.*viewers$"
ATS_EDITOR_REGEX = r"cr-gd-zabbix[-_]?ats.*editors$"

FCS_VIEWER_REGEX = r"cr-gd-zabbix[-_]?fcs.*viewers$"
FCS_EDITOR_REGEX = r"cr-gd-zabbix[-_]?fcs.*editors$"

JET_VIEWER_REGEX = r"cr-gd-zabbix[-_]?jet.*(viewers|app-users)$"
JET_EDITOR_REGEX = r"cr-gd-zabbix[-_]?jet.*(editors|app-admins)$"

# =========================================================
# HTTP SESSION
# =========================================================

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

# =========================================================
# ZABBIX API
# =========================================================

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
        r = self.session.post(
            ZABBIX_URL,
            json=payload,
            headers=headers,
            verify=VERIFY_SSL,
            timeout=30
        )
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

    def get_media_types(self):
        """Get available media types from Zabbix - returns dict by name with mediatypeid"""
        media_types = self.call("mediatype.get", {"output": ["mediatypeid", "name", "type"]})
        return {mt["name"]: mt["mediatypeid"] for mt in media_types}

    def update_provision(self, directory_id, provision_groups=None, provision_media=None):
        if DRY_RUN:
            logging.info(f"DRY RUN provisioning update: groups={len(provision_groups) if provision_groups else 0}, media={len(provision_media) if provision_media else 0}")
            return
        params = {"userdirectoryid": directory_id}
        if provision_groups is not None:
            params["provision_groups"] = provision_groups
        if provision_media is not None:
            params["provision_media"] = provision_media
        self.call("userdirectory.update", params)

# =========================================================
# LDAP
# =========================================================

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

# =========================================================
# ROLE DETECTION
# =========================================================

def detect_role(name):
    n = name.lower()
    if n == SUPER_ADMIN_GROUP.lower():
        return SUPER_ADMIN_ROLE
    if re.search(CSC_EDITOR_REGEX, n):
        return CSC_ROLE_EDITOR
    if re.search(CSC_VIEWER_REGEX, n):
        return CSC_ROLE_VIEWER
    if re.search(ATS_EDITOR_REGEX, n):
        return ATS_ROLE_EDITOR
    if re.search(ATS_VIEWER_REGEX, n):
        return ATS_ROLE_VIEWER
    if re.search(FCS_EDITOR_REGEX, n):
        return FCS_ROLE_EDITOR
    if re.search(FCS_VIEWER_REGEX, n):
        return FCS_ROLE_VIEWER
    if re.search(JET_EDITOR_REGEX, n):
        return JET_ROLE_EDITOR
    if re.search(JET_VIEWER_REGEX, n):
        return JET_ROLE_VIEWER
    if "editors" in n:
        return ROLE_EDITOR
    if "viewers" in n:
        return ROLE_VIEWER
    return ROLE_DEFAULT

# =========================================================
# MEDIA TYPE DETECTION
# =========================================================

def detect_media_config(group_name, available_media_ids, default_media_type_name):
    """
    Determine media config for a group based on name patterns.
    Returns list of media config dicts for provision_media.
    available_media_ids: dict {name: mediatypeid}
    """
    n = group_name.lower()
    media_configs = []
    
    # Check patterns for email-enabled groups
    patterns = [
        (CSC_MEDIA_EMAIL, "CSC"),
        (ATS_MEDIA_EMAIL, "ATS"),
        (FCS_MEDIA_EMAIL, "FCS"),
        (JET_MEDIA_EMAIL, "JET"),
    ]
    
    matched = False
    for pattern, label in patterns:
        if pattern and re.search(pattern.lower(), n):
            matched = True
            logging.debug(f"Group {group_name} matched {label} pattern")
            break
    
    # Determine which media type to use
    media_name = MEDIA_TYPE_EMAIL if matched else default_media_type_name
    
    if media_name and media_name in available_media_ids:
        media_configs.append({
            "mediatypeid": available_media_ids[media_name],  # ← ИСПРАВЛЕНО: mediatypeid вместо mediatype
            "sendto": "",
            "active": 0,
            "severity": 63,
            "period": "1-7,00:00-24:00"
        })
    
    return media_configs

# =========================================================
# NORMALIZE GROUP
# =========================================================

def normalize_group(name):
    n = name.lower()
    n = n.replace("cr-gd-", "")
    n = n.replace("zabbix_", "")
    n = n.replace("zabbix", "")
    n = n.replace("__", "_")
    return n.strip("_")

# =========================================================
# IDEMPOTENT CHECK
# =========================================================

def _normalize_mapping(m):
    """Normalize mapping dict for comparison"""
    return {
        "name": m.get("name"),
        "roleid": m.get("roleid"),
        "user_groups": sorted(
            [(ug.get("usrgrpid"), ug.get("name")) for ug in m.get("user_groups", [])],
            key=lambda x: str(x)
        )
    }

def mappings_equal(old, new):
    """Compare provision_groups lists ignoring order"""
    if len(old) != len(new):
        return False
    old_map = {_normalize_mapping(m)["name"]: _normalize_mapping(m) for m in old}
    new_map = {_normalize_mapping(m)["name"]: _normalize_mapping(m) for m in new}
    return old_map == new_map

def _normalize_media(m):
    """Normalize provision_media dict for comparison"""
    return {
        "name": m.get("name"),
        "mediatypeid": m.get("mediatypeid"),  # ← ИСПРАВЛЕНО
        "sendto": m.get("sendto", ""),
        "active": m.get("active"),
        "severity": m.get("severity"),
        "period": m.get("period"),
        "user_groups": sorted(
            [(ug.get("usrgrpid"), ug.get("name")) for ug in m.get("user_groups", [])],
            key=lambda x: str(x)
        )
    }

def media_mappings_equal(old, new):
    """Compare provision_media lists ignoring order"""
    if len(old) != len(new):
        return False
    old_map = {_normalize_media(m)["name"]: _normalize_media(m) for m in old}
    new_map = {_normalize_media(m)["name"]: _normalize_media(m) for m in new}
    return old_map == new_map

# =========================================================
# MAIN
# =========================================================

def main():
    zbx = ZabbixAPI()

    logging.info("Loading roles")
    roles = zbx.get_roles()

    required_roles = [
        ROLE_DEFAULT, ROLE_VIEWER, ROLE_EDITOR, SUPER_ADMIN_ROLE,
        CSC_ROLE_VIEWER, CSC_ROLE_EDITOR,
        ATS_ROLE_VIEWER, ATS_ROLE_EDITOR,
        FCS_ROLE_VIEWER, FCS_ROLE_EDITOR,
        JET_ROLE_VIEWER, JET_ROLE_EDITOR,
    ]

    for r in required_roles:
        if r not in roles:
            raise Exception(f"Role not found in Zabbix: {r}")
    logging.info("Roles validated")

    logging.info("Loading media types")
    media_type_ids = zbx.get_media_types()  # ← dict {name: mediatypeid}
    logging.info(f"Available media types: {list(media_type_ids.keys())}")
    
    # Проверка что нужный media type существует
    if MEDIA_TYPE_EMAIL not in media_type_ids:
        raise Exception(f"Media type '{MEDIA_TYPE_EMAIL}' not found in Zabbix. Available: {list(media_type_ids.keys())}")
    if DEFAULT_MEDIA_TYPE and DEFAULT_MEDIA_TYPE not in media_type_ids:
        raise Exception(f"Default media type '{DEFAULT_MEDIA_TYPE}' not found in Zabbix")

    directories = zbx.get_directories()
    directory = next((d for d in directories if d["name"] == USER_DIRECTORY), None)
    if not directory:
        raise Exception("User directory not found")
    directory_id = directory["userdirectoryid"]
    logging.info(f"Directory: {USER_DIRECTORY} (ID: {directory_id})")

    zabbix_groups = zbx.get_groups()
    ldap_groups = get_ldap_groups()

    new_mappings = []
    new_provision_media = []

    for ldap_group in ldap_groups:
        zabbix_group = normalize_group(ldap_group)
        role_name = detect_role(ldap_group)
        role_id = roles[role_name]

        # Create Zabbix group if not exists
        if zabbix_group not in zabbix_groups:
            usrgrpid = zbx.create_group(zabbix_group)
            zabbix_groups[zabbix_group] = usrgrpid
            logging.info(f"Created group: {zabbix_group}")
        else:
            usrgrpid = zabbix_groups[zabbix_group]

        # Role mapping
        mapping = {
            "name": ldap_group,
            "roleid": role_id,
            "user_groups": [{"usrgrpid": usrgrpid}]
        }
        new_mappings.append(mapping)

        # Media type mapping - передаём dict {name: id} и имя дефолтного типа
        media_configs = detect_media_config(ldap_group, media_type_ids, DEFAULT_MEDIA_TYPE or MEDIA_TYPE_EMAIL)
        for mc in media_configs:
            provision_media_entry = {
                "name": ldap_group,
                "mediatypeid": mc["mediatypeid"],  # ← Числовой ID, а не объект
                "sendto": "",
                "active": mc["active"],
                "severity": mc["severity"],
                "period": mc["period"],
                "user_groups": [{"usrgrpid": usrgrpid}]
            }
            new_provision_media.append(provision_media_entry)

        media_info = f" + media: mediatypeid={media_configs[0]['mediatypeid']}" if media_configs else ""
        logging.info(f"{ldap_group} → {zabbix_group} → {role_name}{media_info}")

    # Check for changes (idempotent)
    existing_groups = directory.get("provision_groups", [])
    existing_media = directory.get("provision_media", [])

    groups_unchanged = mappings_equal(existing_groups, new_mappings)
    media_unchanged = media_mappings_equal(existing_media, new_provision_media)

    if groups_unchanged and media_unchanged:
        logging.info("No provisioning changes detected")
        logging.info("Sync skipped")
        return

    logging.info("Provisioning changes detected")

    # Merge existing + new
    merged_groups = {m["name"]: m for m in existing_groups}
    for m in new_mappings:
        merged_groups[m["name"]] = m
    final_groups = list(merged_groups.values())

    merged_media = {m["name"]: m for m in existing_media}
    for m in new_provision_media:
        merged_media[m["name"]] = m
    final_media = list(merged_media.values())

    zbx.update_provision(
        directory_id,
        provision_groups=final_groups,
        provision_media=final_media if final_media else None
    )

    logging.info(f"Provision updated: {len(final_groups)} groups, {len(final_media)} media mappings")
    logging.info("SYNC COMPLETED")

# =========================================================
# ENTRY
# =========================================================

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"CRITICAL: {e}", exc_info=True)
        sys.exit(1)
