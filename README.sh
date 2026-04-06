import os
import re
import sys
import logging
import requests

from ldap3 import Server, Connection, ALL, SUBTREE
from dotenv import load_dotenv

load_dotenv("config.env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("sync.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

LDAP_URI = os.getenv("LDAP_URI")
LDAP_PORT = int(os.getenv("LDAP_PORT"))
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_USER = os.getenv("ZABBIX_USER")
ZABBIX_PASS = os.getenv("ZABBIX_PASS")

DEFAULT_USER_GROUP = os.getenv("DEFAULT_USER_GROUP")
ROLE_VIEWER = os.getenv("ROLE_VIEWER")
ROLE_EDITOR = os.getenv("ROLE_EDITOR")

REGEX = r"<REGEX>"

requests.packages.urllib3.disable_warnings()


class ZabbixAPI:

    def __init__(self):
        self.url = ZABBIX_URL
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

        r = requests.post(
            self.url,
            json=payload,
            verify=False,
            timeout=10
        )

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

        r = requests.post(
            self.url,
            json=payload,
            verify=False
        )

        self.auth = r.json()["result"]


def get_ldap_groups():

    logging.info("Connecting to LDAP")

    server = Server(LDAP_URI, port=LDAP_PORT, get_info=ALL)

    conn = Connection(
        server,
        LDAP_USER,
        LDAP_PASS,
        auto_bind=True
    )

    conn.search(
        LDAP_BASE,
        "(<REGEX>)",
        SUBTREE,
        attributes=["cn", "member"]
    )

    groups = []

    for entry in conn.entries:

        cn = str(entry.cn)

        match = re.match(REGEX, cn)

        if not match:
            continue

        members = []

        if "member" in entry:
            members = entry.member.values

        groups.append({
            "cn": cn,
            "system": match.group(1),
            "type": match.group(2),
            "members": members
        })

    logging.info(f"Found {len(groups)} LDAP groups")

    return groups


def extract_login(dn):

    parts = dn.split(",")

    for p in parts:

        if p.startswith("CN="):
            return p.replace("CN=", "").lower()

    return None


def main():

    zbx = ZabbixAPI()

    logging.info("Loading roles")

    roles = zbx.call("role.get", {"output": ["roleid", "name"]})
    role_map = {r["name"]: r["roleid"] for r in roles}

    default_group = zbx.call(
        "usergroup.get",
        {"filter": {"name": DEFAULT_USER_GROUP}}
    )[0]["usrgrpid"]

    groups = get_ldap_groups()

    for g in groups:

        system = g["system"]
        group_type = g["type"]

        user_group_name = f"{system}-{group_type}".lower()

        role_name = ROLE_VIEWER if group_type == "viewers" else ROLE_EDITOR
        roleid = role_map[role_name]

        logging.info(f"Processing {user_group_name}")

        zg = zbx.call(
            "usergroup.get",
            {"filter": {"name": user_group_name}}
        )

        if not zg:

            logging.info(f"Creating user group {user_group_name}")

            zg = zbx.call(
                "usergroup.create",
                {"name": user_group_name}
            )

            usrgrpid = zg["usrgrpids"][0]

        else:
            usrgrpid = zg[0]["usrgrpid"]

        for member in g["members"]:

            login = extract_login(member)

            if not login:
                continue

            logging.info(f"Sync user {login}")

            u = zbx.call(
                "user.get",
                {
                    "filter": {"username": login},
                    "output": ["userid"]
                }
            )

            if not u:

                logging.info(f"Create user {login}")

                zbx.call(
                    "user.create",
                    {
                        "username": login,
                        "roleid": roleid,
                        "usrgrps": [
                            {"usrgrpid": usrgrpid},
                            {"usrgrpid": default_group}
                        ]
                    }
                )

            else:

                logging.info(f"Update user {login}")

                zbx.call(
                    "user.update",
                    {
                        "userid": u[0]["userid"],
                        "roleid": roleid,
                        "usrgrps": [
                            {"usrgrpid": usrgrpid},
                            {"usrgrpid": default_group}
                        ]
                    }
                )


if __name__ == "__main__":
    main()
