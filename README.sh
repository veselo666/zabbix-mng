#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap
import requests
import re
import os
import sys
import logging
from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv("config.env")

# ------------------ НАСТРОЙКА ЛОГИРОВАНИЯ ------------------
logging.basicConfig(
    filename="sync.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# ------------------ ПЕРЕМЕННЫЕ ИЗ КОНФИГА ------------------
LDAP_URI = os.getenv("LDAP_URI")
LDAP_BASE = os.getenv("LDAP_BASE")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")

ZABBIX_URL = os.getenv("ZABBIX_URL")
ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")          # API-токен Zabbix

PREFIX = os.getenv("LDAP_GROUP_PREFIX")

ROLE_VIEWER = os.getenv("ROLE_VIEWER")
ROLE_EDITOR = os.getenv("ROLE_EDITOR")

USER_DIRECTORY = os.getenv("USER_DIRECTORY")

REGEX = r"<REGEX>"

# ------------------ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ ------------------
required_vars = [
    "LDAP_URI", "LDAP_BASE", "LDAP_USER", "LDAP_PASS",
    "ZABBIX_URL", "ZABBIX_TOKEN", "LDAP_GROUP_PREFIX",
    "ROLE_VIEWER", "ROLE_EDITOR", "USER_DIRECTORY"
]
for var in required_vars:
    if not os.getenv(var):
        logging.error(f"Отсутствует обязательная переменная: {var}")
        sys.exit(1)

# ------------------ КЛАСС ДЛЯ РАБОТЫ С ZABBIX API (Bearer Token) ------------------
class ZabbixAPI:
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self.id = 0

    def call(self, method, params):
        """Универсальный вызов метода Zabbix API с Bearer-токеном в заголовке"""
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
        try:
            response = requests.post(self.url, json=payload, headers=headers, verify=False, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Ошибка HTTP-запроса к Zabbix: {e}")
        except ValueError as e:
            raise Exception(f"Неверный JSON от Zabbix: {e}")

        if "error" in data:
            raise Exception(f"Zabbix API error: {data['error']}")
        if "result" not in data:
            raise Exception(f"Zabbix API не вернул 'result' в методе {method}. Ответ: {data}")
        return data["result"]

# ------------------ ПОЛУЧЕНИЕ ГРУПП ИЗ LDAP ------------------
def get_ldap_groups():
    """Возвращает список групп LDAP, соответствующих регулярному выражению"""
    # Отключаем рефералы и строгую проверку сертификатов (при необходимости)
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    try:
        conn = ldap.initialize(LDAP_URI)
        conn.simple_bind_s(LDAP_USER, LDAP_PASS)
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка подключения/аутентификации LDAP: {e}")

    try:
        search_filter = f"(cn={PREFIX}*)"
        result = conn.search_s(
            LDAP_BASE,
            ldap.SCOPE_SUBTREE,
            search_filter,
            ["cn"]
        )
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка поиска в LDAP: {e}")
    finally:
        conn.unbind()

    groups = []
    for dn, entry in result:
        if not entry or "cn" not in entry:
            continue
        cn = entry["cn"][0].decode("utf-8")
        match = re.match(REGEX, cn)
        if match:
            groups.append({
                "ldap_name": cn,
                "system": match.group(1),
                "type": match.group(2)
            })
    logging.info(f"Найдено групп в LDAP: {len(groups)}")
    return groups

# ------------------ ОСНОВНАЯ ФУНКЦИЯ СИНХРОНИЗАЦИИ ------------------
def main():
    logging.info("=== НАЧАЛО СИНХРОНИЗАЦИИ LDAP -> ZABBIX ===")

    # 1. Подключение к Zabbix
    zbx = ZabbixAPI(ZABBIX_URL, ZABBIX_TOKEN)
    # Проверяем работоспособность токена (вызов метода, не требующего прав)
    try:
        zbx.call("apiinfo.version", {})
        logging.info("Успешное подключение к Zabbix API с Bearer-токеном")
    except Exception as e:
        raise Exception(f"Не удалось подключиться к Zabbix API: {e}")

    # 2. Получаем список ролей из Zabbix
    roles = zbx.call("role.get", {"output": ["roleid", "name"]})
    role_map = {role["name"]: role["roleid"] for role in roles}
    if ROLE_VIEWER not in role_map:
        raise Exception(f"Роль '{ROLE_VIEWER}' не найдена в Zabbix")
    if ROLE_EDITOR not in role_map:
        raise Exception(f"Роль '{ROLE_EDITOR}' не найдена в Zabbix")

    # 3. Получаем ID каталога пользователей (LDAP)
    directories = zbx.call("userdirectory.get", {"output": "extend"})
    directory_id = None
    for d in directories:
        if d["name"] == USER_DIRECTORY:
            directory_id = d["userdirectoryid"]
            break
    if not directory_id:
        raise Exception(f"Каталог пользователей '{USER_DIRECTORY}' не найден в Zabbix")

    # 4. Получаем группы из LDAP
    ldap_groups = get_ldap_groups()
    if not ldap_groups:
        logging.warning("Не найдено ни одной группы LDAP, соответствующих шаблону")

    # 5. Синхронизация: создаём группы пользователей Zabbix и маппинги
    for lg in ldap_groups:
        system = lg["system"]
        gtype = lg["type"]
        user_group_name = f"{system}-{gtype}".lower()
        role_name = ROLE_VIEWER if gtype == "viewers" else ROLE_EDITOR
        role_id = role_map[role_name]

        logging.info(f"Обработка группы Zabbix: {user_group_name} (роль {role_name})")

        # Поиск или создание группы пользователей Zabbix
        existing_groups = zbx.call("usergroup.get", {"filter": {"name": user_group_name}})
        if not existing_groups:
            created = zbx.call("usergroup.create", {"name": user_group_name})
            usrgrp_id = created["usrgrpids"][0]
            logging.info(f"Создана новая группа пользователей: {user_group_name}")
        else:
            usrgrp_id = existing_groups[0]["usrgrpid"]

        # Проверяем, существует ли уже маппинг LDAP-группы
        existing_mappings = zbx.call(
            "userdirectorygroup.get",
            {
                "filter": {"name": lg["ldap_name"]},
                "userdirectoryids": directory_id
            }
        )
        if existing_mappings:
            logging.info(f"Маппинг для {lg['ldap_name']} уже существует, пропускаем")
            continue

        # Создаём маппинг
        zbx.call(
            "userdirectorygroup.create",
            {
                "userdirectoryid": directory_id,
                "name": lg["ldap_name"],
                "roleid": role_id,
                "usrgrps": [{"usrgrpid": usrgrp_id}]
            }
        )
        logging.info(f"Создан маппинг: {lg['ldap_name']} -> {user_group_name} (роль {role_name})")

    logging.info("=== СИНХРОНИЗАЦИЯ ЗАВЕРШЕНА УСПЕШНО ===")

# ------------------ ТОЧКА ВХОДА ------------------
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)
