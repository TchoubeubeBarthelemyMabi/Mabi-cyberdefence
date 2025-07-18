import requests, socket
from urllib.parse import urlparse

COMMON_PATHS = ['/admin', '/login', '/phpmyadmin', '/config', '/setup', '/dashboard']

def scan_site(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    report = {
        'headers_status': "",
        'subdomain_status': "",
        'sensitive_status': "",
        'sql_injection_status': "",
        'open_ports_status': "",
        'vuln_count': 0,
        'conclusion': ""
    }

    # 🛡️ Headers de sécurité
    try:
        r = requests.get(url, timeout=5)
        hdr = r.headers
        missing = []
        for h in ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
            if h not in hdr:
                missing.append(h)
        if missing:
            report['headers_status'] = f"❗️ Vulnérable, : {', '.join(missing)}"
            report['vuln_count'] += 1
        else:
            report['headers_status'] = "✅ Sécurisé, tous les headers essentiels présents"
    except:
        report['headers_status'] = "⚠️ Erreur d’analyse des headers"

    # 🌐 Sous-domaines accessibles
    subdomains = []
    for sub in ['www', 'mail', 'ftp']:
        try:
            resp = requests.get(f"http://{sub}.{domain}", timeout=3)
            if resp.status_code < 400:
                subdomains.append(f"{sub}.{domain}")
        except:
            pass
    if subdomains:
        report['subdomain_status'] = f"❗️ Vulnérable, accessibles : {', '.join(subdomains)}"
        report['vuln_count'] += 1
    else:
        report['subdomain_status'] = "✅ Sécurisé, aucun sous-domaine accessible"

    # 🔒 Pages sensibles
    sensitive = []
    for path in COMMON_PATHS:
        try:
            resp = requests.get(url.rstrip('/') + path, timeout=3)
            if resp.status_code == 200:
                sensitive.append(path)
        except:
            pass
    if sensitive:
        report['sensitive_status'] = f"❗️ Pages détectées : {', '.join(sensitive)}"
        report['vuln_count'] += 1
    else:
        report['sensitive_status'] = "✅ Sécurisé - aucune page sensible détectée"

    # 💉 Test d'injection SQL
    try:
        resp = requests.get(url, params={'id': "' OR '1'='1"}, timeout=5)
        txt = resp.text.lower()
        if 'sql' in txt or 'error' in txt:
            report['sql_injection_status'] = "❗️ Possibilité d'injection SQL"
            report['vuln_count'] += 1
        else:
            report['sql_injection_status'] = "✅ Sécurisé contre injection SQL"
    except:
        report['sql_injection_status'] = "⚠️ Test SQL impossible"

    # 📡 Ports ouverts
    ports = []
    for port in [21, 22, 80, 443, 3306]:
        try:
            sock = socket.create_connection((domain, port), timeout=1)
            ports.append(str(port))
            sock.close()
        except:
            pass
    if ports:
        report['open_ports_status'] = f"❗️ Ports ouverts détectés : {', '.join(ports)}"
        report['vuln_count'] += 1
    else:
        report['open_ports_status'] = "✅ Tous les ports sont fermés"

    # 🔚 Conclusion
    if report['vuln_count'] >= 3:
        report['conclusion'] = "❗️ Plusieurs vulnérabilités détectées..."
    elif report['vuln_count'] > 0:
        report['conclusion'] = "⚠️ Quelques vulnérabilités détectées..."
    else:
        report['conclusion'] = "✅ Site bien sécurisé 🎉"

    return report