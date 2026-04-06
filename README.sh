import ldap
import requests
import re
import os
import logging
from dotenv import load_dotenv

load_dotenv("config.env")

logging.basicConfig(
    filename="sync.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

LDAP_URI = os.getenv("LDAP_URI")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_USER = os.getenv("ZABBIX_USER")
ZABBIX_PASS = os.getenv("ZABBIX_PASS")

PREFIX = os.getenv("LDAP_GROUP_PREFIX")

ROLE_VIEWER = os.getenv("ROLE_VIEWER")
ROLE_EDITOR = os.getenv("ROLE_EDITOR")

USER_DIRECTORY = os.getenv("USER_DIRECTORY")

REGEX = r"<RRR>"


class Zabbix:

    def __init__(self):
        self.auth = None
        self.id = 0
        self.login()

    def call(self, method, params):

        self.id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "auth": self.auth,
            "id": self.id
        }

        r = requests.post(ZABBIX_URL, json=payload, verify=False)

        data = r.json()

        if "error" in data:
            raise Exception(data["error"])

        return data["result"]

    def login(self):
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "username": ZABBIX_USER,
            "password": ZABBIX_PASS
        },
        "id": 1
    }
    r = requests.post(ZABBIX_URL, json=payload, verify=False)
    data = r.json()

    # Проверяем, есть ли ошибка в ответе
    if "error" in data:
        error_msg = data["error"].get("data", "Неизвестная ошибка")
        raise Exception(f"Ошибка авторизации Zabbix API: {error_msg}")

    # Если ошибки нет, извлекаем токен
    self.auth = data.get("result")
    if not self.auth:
        raise Exception("Токен авторизации не получен, проверьте URL и данные для входа.")


def ldap_groups():

    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    conn = ldap.initialize(LDAP_URI)
    conn.simple_bind_s(LDAP_USER, LDAP_PASS)

    result = conn.search_s(
        LDAP_BASE,
        ldap.SCOPE_SUBTREE,
        f"(cn={PREFIX}*)",
        ["cn"]
    )

    groups = []

    for dn, entry in result:

        if not entry:
            continue

        cn = entry["cn"][0].decode()

        m = re.match(REGEX, cn)

        if m:
            groups.append({
                "ldap": cn,
                "system": m.group(1),
                "type": m.group(2)
            })

    return groups


def main():

    zbx = Zabbix()

    roles = zbx.call("role.get", {"output": ["roleid", "name"]})
    role_map = {r["name"]: r["roleid"] for r in roles}

    directories = zbx.call("userdirectory.get", {"output": "extend"})

    directory_id = None

    for d in directories:
        if d["name"] == USER_DIRECTORY:
            directory_id = d["userdirectoryid"]

    if not directory_id:
        raise Exception("LDAP directory not found")

    groups = ldap_groups()

    for g in groups:

        system = g["system"]
        gtype = g["type"]

        user_group = f"{system}-{gtype}".lower()

        role_name = ROLE_VIEWER if gtype == "viewers" else ROLE_EDITOR
        roleid = role_map[role_name]

        logging.info(f"Processing {user_group}")

        ug = zbx.call(
            "usergroup.get",
            {"filter": {"name": user_group}}
        )

        if not ug:

            res = zbx.call(
                "usergroup.create",
                {"name": user_group}
            )

            usrgrpid = res["usrgrpids"][0]

        else:
            usrgrpid = ug[0]["usrgrpid"]

        mappings = zbx.call(
            "userdirectorygroup.get",
            {
                "filter": {"name": g["ldap"]},
                "userdirectoryids": directory_id
            }
        )

        if mappings:
            continue

        logging.info(f"Create mapping {g['ldap']}")

        zbx.call(
            "userdirectorygroup.create",
            {
                "userdirectoryid": directory_id,
                "name": g["ldap"],
                "roleid": roleid,
                "usrgrps": [{"usrgrpid": usrgrpid}]
            }
        )


if __name__ == "__main__":
    main()
