#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import re
import os
import logging
from dotenv import load_dotenv

# Загрузка переменных из config.env
load_dotenv("config.env")

# Настройка логирования
logging.basicConfig(
    filename="sync.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# --- Чтение переменных окружения ---
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

REGEX = r"<REGEX>"
# --- Класс для работы с Zabbix API ---
class Zabbix:
    def __init__(self):
        self.auth = None
        self.id = 0
        self.login()

    def call(self, method, params):
        """Универсальный вызов метода Zabbix API"""
        self.id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "auth": self.auth,
            "id": self.id
        }
        try:
            r = requests.post(ZABBIX_URL, json=payload, verify=False)
            data = r.json()
        except Exception as e:
            raise Exception(f"Ошибка соединения с Zabbix API: {e}")

        if "error" in data:
            raise Exception(f"Zabbix API error: {data['error']}")
        if "result" not in data:
            raise Exception(f"Zabbix API не вернул 'result' в методе {method}. Ответ: {data}")
        return data["result"]

    def login(self):
    """Авторизация в Zabbix с использованием API-токена"""
    if not ZABBIX_TOKEN:
        raise Exception("API-токен не найден в config.env. Добавьте переменную ZABBIX_TOKEN.")
    
    # Токен используется сразу при создании сессии, метод user.login не нужен
    self.auth = ZABBIX_TOKEN 
    # Небольшая проверка: пытаемся получить версию API, чтобы убедиться, что токен работает
    try:
        self.call("apiinfo.version", {})
    except Exception as e:
        raise Exception(f"Не удалось авторизоваться с использованием API-токена: {e}")

# --- Получение групп из LDAP ---
def ldap_groups():
    """Возвращает список групп LDAP, соответствующих REGEX"""
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    try:
        conn = ldap.initialize(LDAP_URI)
        conn.simple_bind_s(LDAP_USER, LDAP_PASS)
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка подключения к LDAP: {e}")

    try:
        result = conn.search_s(
            LDAP_BASE,
            ldap.SCOPE_SUBTREE,
            f"(cn={PREFIX}*)",
            ["cn"]
        )
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка поиска в LDAP: {e}")

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

# --- Основная функция синхронизации ---
def main():
    logging.info("=== Начало синхронизации ===")

    # 1. Подключение к Zabbix
    zbx = Zabbix()

    # 2. Получение ролей из Zabbix
    roles = zbx.call("role.get", {"output": ["roleid", "name"]})
    role_map = {r["name"]: r["roleid"] for r in roles}
    if ROLE_VIEWER not in role_map:
        raise Exception(f"Роль '{ROLE_VIEWER}' не найдена в Zabbix")
    if ROLE_EDITOR not in role_map:
        raise Exception(f"Роль '{ROLE_EDITOR}' не найдена в Zabbix")

    # 3. Получение каталога пользователей (LDAP)
    directories = zbx.call("userdirectory.get", {"output": "extend"})
    directory_id = None
    for d in directories:
        if d["name"] == USER_DIRECTORY:
            directory_id = d["userdirectoryid"]
            break
    if not directory_id:
        raise Exception(f"Каталог пользователей '{USER_DIRECTORY}' не найден в Zabbix")

    # 4. Получение групп из LDAP
    groups = ldap_groups()
    logging.info(f"Найдено групп LDAP: {len(groups)}")

    # 5. Синхронизация
    for g in groups:
        system = g["system"]
        gtype = g["type"]
        user_group = f"{system}-{gtype}".lower()
        role_name = ROLE_VIEWER if gtype == "viewers" else ROLE_EDITOR
        roleid = role_map[role_name]

        logging.info(f"Обработка группы Zabbix: {user_group} (роль {role_name})")

        # Поиск или создание группы пользователей Zabbix
        ug = zbx.call("usergroup.get", {"filter": {"name": user_group}})
        if not ug:
            res = zbx.call("usergroup.create", {"name": user_group})
            usrgrpid = res["usrgrpids"][0]
            logging.info(f"Создана группа пользователей: {user_group}")
        else:
            usrgrpid = ug[0]["usrgrpid"]

        # Проверка существования маппинга LDAP-группы
        mappings = zbx.call(
            "userdirectorygroup.get",
            {
                "filter": {"name": g["ldap"]},
                "userdirectoryids": directory_id
            }
        )
        if mappings:
            logging.info(f"Маппинг для {g['ldap']} уже существует, пропускаем")
            continue

        # Создание маппинга
        zbx.call(
            "userdirectorygroup.create",
            {
                "userdirectoryid": directory_id,
                "name": g["ldap"],
                "roleid": roleid,
                "usrgrps": [{"usrgrpid": usrgrpid}]
            }
        )
        logging.info(f"Создан маппинг {g['ldap']} -> {user_group} (роль {role_name})")

    logging.info("=== Синхронизация завершена ===")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        print(f"Ошибка: {e}")
        exit(1)
