#!/usr/bin/env python3
"""
ZAP Authenticated Security Scan - Python Script
Alternatywna metoda do uruchomienia uwierzytelnionego skanu ZAP
Wymaga: pip install python-owasp-zap-v2.4
"""

import time
import sys
from zapv2 import ZAPv2

# Konfiguracja
TARGET_URL = "http://localhost:8000"
ZAP_PROXY = "http://localhost:8090"
CONTEXT_NAME = "Forum App Authenticated"
USER_NAME = "admin"
USER_PASSWORD = "Admin@123"

def main():
    print("=" * 60)
    print("ZAP Authenticated Security Scan - Python")
    print("=" * 60)

    # Połącz z ZAP (musi być uruchomiony wcześniej)
    print("\n[1/8] Łączenie z ZAP...")
    try:
        zap = ZAPv2(proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})
        print(f"✓ Połączono z ZAP: {zap.core.version}")
    except Exception as e:
        print(f"✗ Nie można połączyć z ZAP na {ZAP_PROXY}")
        print("Uruchom ZAP: docker run -u zap -p 8090:8090 -d ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true")
        sys.exit(1)

    # Utwórz kontekst
    print("\n[2/8] Tworzenie kontekstu...")
    context_id = zap.context.new_context(CONTEXT_NAME)
    zap.context.include_in_context(CONTEXT_NAME, f"{TARGET_URL}.*")
    zap.context.exclude_from_context(CONTEXT_NAME, f"{TARGET_URL}/logout.*")
    zap.context.exclude_from_context(CONTEXT_NAME, f"{TARGET_URL}/static/.*")
    zap.context.exclude_from_context(CONTEXT_NAME, f"{TARGET_URL}/uploads/.*")
    print(f"✓ Kontekst utworzony: {CONTEXT_NAME}")

    # Konfiguruj uwierzytelnienie form-based
    print("\n[3/8] Konfiguracja uwierzytelnienia...")
    login_url = f"{TARGET_URL}/login"
    login_data = f"username={USER_NAME}&password={USER_PASSWORD}"

    zap.authentication.set_authentication_method(
        context_id,
        'formBasedAuthentication',
        f'loginUrl={login_url}&loginRequestData={login_data}'
    )

    # Ustaw weryfikację logowania
    zap.authentication.set_logged_in_indicator(context_id, "username")
    zap.authentication.set_logged_out_indicator(context_id, "login")
    print("✓ Uwierzytelnienie skonfigurowane")

    # Dodaj użytkownika
    print("\n[4/8] Dodawanie użytkownika testowego...")
    user_id = zap.users.new_user(context_id, USER_NAME)
    zap.users.set_authentication_credentials(
        context_id,
        user_id,
        f"username={USER_NAME}&password={USER_PASSWORD}"
    )
    zap.users.set_user_enabled(context_id, user_id, True)
    zap.forcedUser.set_forced_user(context_id, user_id)
    zap.forcedUser.set_forced_user_mode_enabled(True)
    print(f"✓ Użytkownik dodany: {USER_NAME}")

    # Spider (crawling)
    print("\n[5/8] Spider - przeszukiwanie aplikacji...")
    print("To może potrwać kilka minut...")
    scan_id = zap.spider.scan_as_user(context_id, user_id, TARGET_URL, recurse=True)

    # Czekaj na zakończenie spider
    while int(zap.spider.status(scan_id)) < 100:
        progress = zap.spider.status(scan_id)
        print(f"  Spider progress: {progress}%", end='\r')
        time.sleep(2)

    print("\n✓ Spider zakończony")
    print(f"  Znaleziono URLs: {len(zap.core.urls(TARGET_URL))}")

    # Passive Scan
    print("\n[6/8] Passive Scan...")
    while int(zap.pscan.records_to_scan) > 0:
        remaining = zap.pscan.records_to_scan
        print(f"  Pozostało do przeskanowania: {remaining}", end='\r')
        time.sleep(2)
    print("\n✓ Passive scan zakończony")

    # Active Scan
    print("\n[7/8] Active Scan (może potrwać 10-20 minut)...")
    scan_id = zap.ascan.scan_as_user(context_id, user_id, TARGET_URL, recurse=True)

    # Czekaj na zakończenie active scan
    while int(zap.ascan.status(scan_id)) < 100:
        progress = zap.ascan.status(scan_id)
        print(f"  Active scan progress: {progress}%", end='\r')
        time.sleep(5)

    print("\n✓ Active scan zakończony")

    # Generuj raporty
    print("\n[8/8] Generowanie raportów...")

    # HTML Report
    html_report = zap.core.htmlreport()
    with open('zap-reports/zap-python-report.html', 'w') as f:
        f.write(html_report)
    print("✓ HTML: zap-reports/zap-python-report.html")

    # JSON Report
    import json
    alerts = zap.core.alerts(TARGET_URL)
    with open('zap-reports/zap-python-report.json', 'w') as f:
        json.dump(alerts, f, indent=2)
    print("✓ JSON: zap-reports/zap-python-report.json")

    # Podsumowanie
    print("\n" + "=" * 60)
    print("Podsumowanie wykrytych podatności:")
    print("=" * 60)

    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for alert in alerts:
        risk = alert.get('risk', 'Informational')
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    print(f"🔴 High:          {risk_counts['High']}")
    print(f"🟠 Medium:        {risk_counts['Medium']}")
    print(f"🟡 Low:           {risk_counts['Low']}")
    print(f"🔵 Informational: {risk_counts['Informational']}")

    print("\n" + "=" * 60)
    print("Skan zakończony!")
    print("=" * 60)

if __name__ == "__main__":
    main()
