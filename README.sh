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

    # --- Параметры постраничного поиска ---
    page_size = 500
    cookie = None
    groups = []

    try:
        while True:
            msgid = conn.search_ext(
                LDAP_GROUP_BASE,
                ldap.SCOPE_SUBTREE,
                LDAP_FILTER,
                ["cn"],
                serverctrls=[ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie=cookie)]
            )
            rtype, rdata, rmsgid, serverctrls = conn.result3(msgid)
            for dn, entry in rdata:
                if not entry or "cn" not in entry:
                    continue
                cn_raw = entry["cn"][0]
                cn = cn_raw.decode("utf-8") if isinstance(cn_raw, bytes) else cn_raw
                groups.append(cn)

            # Обновляем cookie
            cookie = None
            for ctrl in serverctrls:
                if ctrl.controlType == ldap.controls.SimplePagedResultsControl.controlType:
                    cookie = ctrl.cookie
            if not cookie:
                break
    except ldap.LDAPError as e:
        raise Exception(f"Ошибка поиска LDAP: {e}")
    finally:
        conn.unbind()

    logging.info(f"Найдено LDAP-групп: {len(groups)}")
    return groups
