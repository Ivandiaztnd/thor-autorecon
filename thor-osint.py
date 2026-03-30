#!/usr/bin/env python3
# ============================================================
#  THOR OSINT MODULE v1.0
#  crt.sh · Shodan · Censys · SecurityTrails · DNS · Whois
#  Gestión automática de API keys
#  Importable desde thor-auto.py o ejecutable standalone
# ============================================================

import json, re, socket, time, urllib.request, urllib.parse
import urllib.error, ssl, os, sys
from pathlib import Path
from datetime import datetime

# ── config de keys ───────────────────────────────────────────
KEYS_FILE = Path("/etc/thor/osint_keys.json")

C = '\033[0;36m'; G = '\033[1;32m'; Y = '\033[1;33m'
R = '\033[1;31m'; W = '\033[1;37m'; D = '\033[0;90m'
M = '\033[1;35m'; N = '\033[0m'

def osint_status(msg, level="info"):
    icons = {"info": f"{Y}[OSINT]{N}", "ok": f"{G}[OSINT]{N}",
             "fail": f"{R}[OSINT]{N}", "key": f"{M}[KEY]{N}",
             "find": f"{G}[!!]{N}"}
    print(f"  {icons.get(level,'[?]')} {msg}")

# ════════════════════════════════════════════════════════════
#  GESTIÓN DE API KEYS
# ════════════════════════════════════════════════════════════

def load_keys():
    """Cargar keys guardadas"""
    if KEYS_FILE.exists():
        try:
            return json.loads(KEYS_FILE.read_text())
        except Exception:
            pass
    return {}

def save_keys(keys):
    """Guardar keys en archivo protegido"""
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEYS_FILE.write_text(json.dumps(keys, indent=2))
    KEYS_FILE.chmod(0o600)  # solo root puede leer

def get_key(service, keys):
    """Obtener key de un servicio — pedir si no existe"""
    if service in keys and keys[service]:
        return keys[service]
    return None

def setup_keys_interactive(keys):
    """
    Asistente interactivo para configurar API keys.
    Muestra URLs de registro y pide las keys.
    """
    print(f"\n  {M}━━━ CONFIGURACIÓN DE API KEYS OSINT ━━━━━━━━━━━━━━━━━━━{N}\n")

    services = {
        "shodan": {
            "name":    "Shodan",
            "url":     "https://account.shodan.io/register",
            "free":    "100 queries/mes, datos de puertos y banners",
            "key_url": "https://account.shodan.io → My Account → API Key"
        },
        "censys": {
            "name":    "Censys",
            "url":     "https://accounts.censys.io/register",
            "free":    "250 queries/mes, IPv4 + certificados",
            "key_url": "https://search.censys.io/account/api → API ID + Secret"
        },
        "securitytrails": {
            "name":    "SecurityTrails",
            "url":     "https://securitytrails.com/app/signup",
            "free":    "50 queries/mes, DNS histórico",
            "key_url": "https://securitytrails.com/app/account/credentials"
        }
    }

    for svc_id, info in services.items():
        current = keys.get(svc_id, "")
        status_str = f"{G}configurada{N}" if current else f"{Y}no configurada{N}"
        print(f"  {W}{info['name']}{N} — {status_str}")
        print(f"  {D}  Plan gratuito: {info['free']}{N}")
        print(f"  {D}  Registro: {info['url']}{N}")
        print(f"  {D}  Obtener key: {info['key_url']}{N}")
        print()

        if current:
            try:
                ans = input(f"  ¿Actualizar key de {info['name']}? [s/N]: ").strip().lower()
                if ans not in ("s","si","sí","y"):
                    continue
            except (KeyboardInterrupt, EOFError):
                print()
                continue

        try:
            if svc_id == "censys":
                print(f"  {D}Censys necesita API ID y Secret separados{N}")
                api_id = input(f"  API ID [{info['name']}] (Enter para omitir): ").strip()
                if api_id:
                    secret = input(f"  API Secret [{info['name']}]: ").strip()
                    if secret:
                        keys[svc_id] = f"{api_id}:{secret}"
                        print(f"  {G}[✓]{N} Censys configurado")
            else:
                key = input(f"  API Key [{info['name']}] (Enter para omitir): ").strip()
                if key:
                    keys[svc_id] = key
                    print(f"  {G}[✓]{N} {info['name']} configurado")
                else:
                    print(f"  {D}Omitido{N}")
        except (KeyboardInterrupt, EOFError):
            print()

        print()

    save_keys(keys)
    print(f"  {G}[✓]{N} Keys guardadas en {KEYS_FILE}")
    return keys

def http_get(url, headers=None, timeout=15):
    """HTTP GET con manejo de errores"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Mozilla/5.0 (compatible; security-scanner/1.0)"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None

# ════════════════════════════════════════════════════════════
#  FUENTES OSINT
# ════════════════════════════════════════════════════════════

class OsintResult:
    """Contenedor de resultados OSINT"""
    def __init__(self):
        self.subdomains    = set()   # subdominios encontrados
        self.ips           = set()   # IPs asociadas
        self.ports         = {}      # ip → [ports]
        self.certs         = []      # certificados SSL
        self.dns_records   = {}      # tipo → [registros]
        self.services      = {}      # ip:port → {service, banner, cves}
        self.cves_external = []      # CVEs desde fuentes externas
        self.banners       = {}      # ip:port → banner
        self.technologies  = set()   # tecnologías detectadas
        self.emails        = set()   # emails encontrados
        self.org_info      = {}      # info de la organización
        self.shodan_data   = {}      # datos raw de Shodan
        self.censys_data   = {}      # datos raw de Censys
        self.sources_used  = []      # fuentes que respondieron
        self.has_findings  = False   # flag para decisión post-scan

    def to_dict(self):
        return {
            "subdomains":    list(self.subdomains),
            "ips":           list(self.ips),
            "ports":         self.ports,
            "certs":         self.certs[:10],
            "dns_records":   self.dns_records,
            "services":      self.services,
            "cves_external": self.cves_external,
            "technologies":  list(self.technologies),
            "emails":        list(self.emails),
            "org_info":      self.org_info,
            "sources_used":  self.sources_used,
            "has_findings":  self.has_findings
        }

# ── 1. crt.sh ────────────────────────────────────────────────

def query_crtsh(target, result):
    """
    crt.sh — base de datos pública de certificados SSL.
    Sin API key. Devuelve subdominios y fechas de cert.
    """
    osint_status("crt.sh — certificados SSL...", "info")

    # Extraer dominio base si es IP
    domain = target
    try:
        socket.inet_aton(target)
        osint_status("crt.sh: target es IP, buscando por IP...", "info")
        url = f"https://crt.sh/?q={target}&output=json"
    except socket.error:
        # Es un hostname — buscar dominio base
        parts = target.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else target
        url = f"https://crt.sh/?q=%.{domain}&output=json"

    data = http_get(url, timeout=20)
    if not data:
        osint_status("crt.sh sin respuesta", "fail")
        return

    try:
        entries = json.loads(data)
    except Exception:
        osint_status("crt.sh respuesta no parseable", "fail")
        return

    seen = set()
    for entry in entries[:200]:  # máximo 200 entradas
        name = entry.get("name_value","").lower()
        issuer = entry.get("issuer_name","")
        not_before = entry.get("not_before","")
        not_after  = entry.get("not_after","")

        # Limpiar wildcards
        names = [n.strip().lstrip("*.") for n in name.split("\n") if n.strip()]

        for n in names:
            if n and n not in seen and domain in n:
                seen.add(n)
                result.subdomains.add(n)
                result.certs.append({
                    "domain": n, "issuer": issuer,
                    "not_before": not_before, "not_after": not_after
                })

    if result.subdomains:
        result.sources_used.append("crt.sh")
        result.has_findings = True
        osint_status(f"crt.sh → {len(result.subdomains)} subdominios/certs", "ok")
        for sub in sorted(result.subdomains)[:8]:
            osint_status(f"  {sub}", "find")
        if len(result.subdomains) > 8:
            osint_status(f"  ... y {len(result.subdomains)-8} más", "info")
    else:
        osint_status("crt.sh → sin resultados", "info")

# ── 2. SecurityTrails DNS ────────────────────────────────────

def query_securitytrails(target, result, api_key=None):
    """
    SecurityTrails — registros DNS históricos y subdominios.
    Sin key: endpoint público básico.
    Con key: historial completo, registros A/MX/NS/TXT/SOA.
    """
    osint_status("SecurityTrails DNS...", "info")

    # Extraer dominio base
    try:
        socket.inet_aton(target)
        domain = target  # Es IP
        endpoint = f"https://api.securitytrails.com/v1/ips/{target}"
    except socket.error:
        parts = target.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else target
        endpoint = f"https://api.securitytrails.com/v1/domain/{domain}"

    headers = {"User-Agent": "Mozilla/5.0"}
    if api_key:
        headers["APIKEY"] = api_key

    # Sin key — usar endpoint público de subdominios
    if not api_key:
        # Fallback: DNS lookup con múltiples registros via dig
        osint_status("SecurityTrails sin key — usando DNS lookup extendido", "info")
        _query_dns_extended(target, domain, result)
        return

    data = http_get(endpoint, headers=headers, timeout=15)
    if not data:
        osint_status("SecurityTrails sin respuesta", "fail")
        return

    try:
        parsed = json.loads(data)
    except Exception:
        osint_status("SecurityTrails respuesta no parseable", "fail")
        return

    # Procesar respuesta
    records = parsed.get("current_dns", {})
    for rtype, rdata in records.items():
        values = rdata.get("values",[]) if isinstance(rdata, dict) else []
        result.dns_records[rtype] = []
        for v in values:
            if isinstance(v, dict):
                val = v.get("ip") or v.get("hostname") or v.get("value","")
                if val:
                    result.dns_records[rtype].append(val)
                    if rtype == "a" and val:
                        result.ips.add(val)

    # Subdominios
    subs = parsed.get("subdomains", [])
    for sub in subs:
        result.subdomains.add(f"{sub}.{domain}")

    if records or subs:
        result.sources_used.append("SecurityTrails")
        result.has_findings = True
        osint_status(f"SecurityTrails → {len(records)} tipos DNS, {len(subs)} subdominios", "ok")
        for rtype, vals in result.dns_records.items():
            if vals:
                osint_status(f"  {rtype.upper()}: {', '.join(vals[:3])}", "ok")
    else:
        osint_status("SecurityTrails → sin resultados", "info")

def _query_dns_extended(target, domain, result):
    """DNS lookup extendido sin APIs externas"""
    import subprocess

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    for rtype in record_types:
        try:
            r = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                vals = [v.strip() for v in r.stdout.strip().splitlines() if v.strip()]
                result.dns_records[rtype] = vals
                if rtype == "A":
                    result.ips.update(vals)
                    osint_status(f"  DNS {rtype}: {', '.join(vals[:3])}", "ok")
        except Exception:
            pass

    # Buscar subdominios comunes via DNS brute
    common_subs = ["www","mail","ftp","ssh","admin","api","dev","staging",
                   "vpn","remote","webmail","portal","app","db","cloud",
                   "mx","ns1","ns2","smtp","pop","imap"]

    found_subs = []
    for sub in common_subs:
        try:
            fqdn = f"{sub}.{domain}"
            ip = socket.gethostbyname(fqdn)
            result.subdomains.add(fqdn)
            result.ips.add(ip)
            found_subs.append(f"{fqdn} → {ip}")
        except Exception:
            pass

    if found_subs:
        result.sources_used.append("DNS-brute")
        result.has_findings = True
        osint_status(f"DNS brute → {len(found_subs)} subdominios activos", "ok")
        for s in found_subs[:5]:
            osint_status(f"  {s}", "find")

    if result.dns_records:
        result.sources_used.append("DNS-extended")
        result.has_findings = True

# ── 3. Shodan ────────────────────────────────────────────────

def query_shodan(target, result, api_key):
    """
    Shodan — banners, puertos, CVEs, tecnologías.
    Requiere API key (plan gratuito = 100 queries/mes).
    """
    if not api_key:
        osint_status("Shodan sin API key — omitiendo", "info")
        return

    osint_status(f"Shodan → {target}...", "info")

    # Resolver a IP si es hostname
    ip = target
    try:
        socket.inet_aton(target)
    except socket.error:
        try:
            ip = socket.gethostbyname(target)
            osint_status(f"Shodan: resolvió {target} → {ip}", "info")
        except Exception:
            osint_status("Shodan: no se pudo resolver el hostname", "fail")
            return

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    data = http_get(url, timeout=20)

    if not data:
        osint_status("Shodan sin respuesta", "fail")
        return

    try:
        parsed = json.loads(data)
    except Exception:
        osint_status("Shodan respuesta no parseable", "fail")
        return

    if "error" in parsed:
        osint_status(f"Shodan error: {parsed['error']}", "fail")
        return

    result.shodan_data = parsed

    # Organización
    result.org_info["shodan_org"]     = parsed.get("org","")
    result.org_info["shodan_isp"]     = parsed.get("isp","")
    result.org_info["shodan_country"] = parsed.get("country_name","")
    result.org_info["shodan_city"]    = parsed.get("city","")
    result.org_info["asn"]            = parsed.get("asn","")

    osint_status(f"  Org: {parsed.get('org','')} | ASN: {parsed.get('asn','')}", "ok")
    osint_status(f"  País: {parsed.get('country_name','')} | Ciudad: {parsed.get('city','')}", "ok")

    # OS
    if parsed.get("os"):
        result.org_info["os"] = parsed["os"]
        osint_status(f"  OS: {parsed['os']}", "ok")

    # Puertos y servicios
    ports_found = parsed.get("ports",[])
    if ports_found:
        result.ports[ip] = ports_found
        result.ips.add(ip)
        result.has_findings = True
        osint_status(f"  Puertos visibles en Shodan: {ports_found}", "find")

    # Servicios con banners
    for svc in parsed.get("data",[]):
        port    = svc.get("port",0)
        banner  = svc.get("data","").strip()[:200]
        svc_key = f"{ip}:{port}"

        result.services[svc_key] = {
            "port":     port,
            "transport": svc.get("transport","tcp"),
            "product":  svc.get("product",""),
            "version":  svc.get("version",""),
            "banner":   banner
        }
        result.banners[svc_key] = banner

        if svc.get("product"):
            result.technologies.add(f"{svc.get('product','')} {svc.get('version','')}".strip())

        # SSL info
        ssl_info = svc.get("ssl",{})
        if ssl_info and ssl_info.get("cert"):
            cert = ssl_info["cert"]
            subject = cert.get("subject",{})
            cn = subject.get("CN","")
            if cn:
                result.subdomains.add(cn.lstrip("*."))

        # CVEs desde Shodan
        for vuln_id in svc.get("vulns",{}).keys():
            vuln_data = svc["vulns"][vuln_id]
            result.cves_external.append({
                "cve":    vuln_id,
                "cvss":   str(vuln_data.get("cvss","")),
                "source": "Shodan",
                "port":   port,
                "summary": vuln_data.get("summary","")[:150]
            })
            result.has_findings = True

    # CVEs globales del host
    for vuln_id, vuln_data in parsed.get("vulns",{}).items():
        if vuln_id not in [c["cve"] for c in result.cves_external]:
            result.cves_external.append({
                "cve":    vuln_id,
                "cvss":   str(vuln_data.get("cvss","")),
                "source": "Shodan",
                "port":   0,
                "summary": vuln_data.get("summary","")[:150]
            })

    # Tags especiales (honeypot, tor, etc.)
    tags = parsed.get("tags",[])
    if tags:
        osint_status(f"  Tags Shodan: {', '.join(tags)}", "info")
        if "honeypot" in tags:
            osint_status("  ADVERTENCIA: Shodan marca este host como HONEYPOT", "fail")

    cve_count = len(result.cves_external)
    if cve_count > 0:
        osint_status(f"  CVEs en Shodan: {cve_count}", "find")
        for c in result.cves_external[:3]:
            osint_status(f"    {c['cve']} (CVSS {c['cvss']}) — {c['summary'][:60]}", "find")

    result.sources_used.append("Shodan")

# ── 4. Censys ────────────────────────────────────────────────

def query_censys(target, result, api_key):
    """
    Censys — IPv4 scan data, certificados, puertos.
    Requiere API ID:Secret (plan gratuito = 250 queries/mes).
    """
    if not api_key or ":" not in api_key:
        osint_status("Censys sin API key — omitiendo", "info")
        return

    osint_status(f"Censys → {target}...", "info")

    api_id, api_secret = api_key.split(":", 1)

    # Resolver a IP
    ip = target
    try:
        socket.inet_aton(target)
    except socket.error:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            osint_status("Censys: no se pudo resolver el hostname", "fail")
            return

    import base64
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type":  "application/json",
        "User-Agent":    "thor-osint/1.0"
    }

    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    data = http_get(url, headers=headers, timeout=20)

    if not data:
        osint_status("Censys sin respuesta", "fail")
        return

    try:
        parsed = json.loads(data)
    except Exception:
        osint_status("Censys respuesta no parseable", "fail")
        return

    if parsed.get("code") and parsed["code"] != 200:
        osint_status(f"Censys error: {parsed.get('message','')}", "fail")
        return

    host_data = parsed.get("result",{})
    result.censys_data = host_data

    # Servicios
    services = host_data.get("services",[])
    for svc in services:
        port     = svc.get("port",0)
        proto    = svc.get("transport_protocol","tcp").lower()
        svc_name = svc.get("service_name","")
        svc_key  = f"{ip}:{port}"

        result.services[svc_key] = {
            "port":      port,
            "transport": proto,
            "product":   svc_name,
            "version":   svc.get("software",[{}])[0].get("version","") if svc.get("software") else "",
            "banner":    svc.get("banner","")[:200]
        }

        if ip not in result.ports:
            result.ports[ip] = []
        result.ports[ip].append(port)
        result.ips.add(ip)
        result.has_findings = True

        # TLS/Certificados
        tls = svc.get("tls",{})
        if tls:
            cert = tls.get("certificates",{}).get("leaf_data",{})
            names = cert.get("names",[])
            for n in names:
                result.subdomains.add(n.lstrip("*."))

        # Tecnologías
        for sw in svc.get("software",[]):
            tech = f"{sw.get('product','')} {sw.get('version','')}".strip()
            if tech:
                result.technologies.add(tech)

    ports_list = result.ports.get(ip,[])
    osint_status(f"Censys → {len(services)} servicios, puertos: {ports_list}", "ok")
    result.sources_used.append("Censys")

# ── 5. Análisis de emails y org ──────────────────────────────

def extract_emails_from_whois(whois_text, result):
    """Extraer emails del output de whois"""
    emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', whois_text)
    for email in emails:
        if not email.endswith((".png",".jpg",".gif")):
            result.emails.add(email.lower())

# ════════════════════════════════════════════════════════════
#  ORQUESTADOR PRINCIPAL
# ════════════════════════════════════════════════════════════

def run_osint(target, hostname=None, outdir=None, keys=None):
    """
    Ejecutar todas las fuentes OSINT disponibles.
    Retorna OsintResult con todos los hallazgos.
    """
    if keys is None:
        keys = load_keys()

    result = OsintResult()
    result.target   = target
    result.hostname = hostname

    domain = hostname or target

    osint_status(f"Iniciando OSINT para {domain} ({target})", "info")
    print()

    # 1. crt.sh — siempre, sin key
    query_crtsh(domain, result)
    print()

    # 2. DNS extendido — siempre, sin key
    try:
        socket.inet_aton(target)
        is_ip = True
    except socket.error:
        is_ip = False

    if not is_ip:
        parts = domain.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        _query_dns_extended(target, base_domain, result)
        print()

    # 3. Whois — extraer emails y org
    import subprocess
    try:
        r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=30)
        if r.stdout:
            extract_emails_from_whois(r.stdout, result)
            # Extraer info de org
            for line in r.stdout.splitlines():
                for field in ["OrgName","org-name","owner","Organisation","registrant"]:
                    if re.match(f"^{field}:", line, re.I):
                        result.org_info["org"] = line.split(":",1)[1].strip()
            if result.emails:
                osint_status(f"Whois emails: {', '.join(list(result.emails)[:3])}", "ok")
                result.has_findings = True
    except Exception:
        pass

    # 4. SecurityTrails — con o sin key
    st_key = keys.get("securitytrails")
    query_securitytrails(domain, result, st_key)
    print()

    # 5. Shodan — con key
    sh_key = keys.get("shodan")
    query_shodan(target, result, sh_key)
    print()

    # 6. Censys — con key
    ce_key = keys.get("censys")
    query_censys(target, result, ce_key)
    print()

    # ── Consolidar IPs de subdominios ────────────────────────
    new_ips = set()
    for sub in list(result.subdomains)[:20]:  # resolver máx 20
        try:
            ip_resolved = socket.gethostbyname(sub)
            new_ips.add(ip_resolved)
        except Exception:
            pass
    if new_ips:
        result.ips.update(new_ips)
        osint_status(f"IPs adicionales resueltas: {new_ips}", "ok")

    # ── Puertos sugeridos para scan sin detección ────────────
    all_known_ports = set()
    for ip_ports in result.ports.values():
        all_known_ports.update(ip_ports)
    result.suggested_ports = sorted(all_known_ports) if all_known_ports else \
                             [80, 443, 8080, 8443, 22, 21, 25, 3389]

    # ── Resumen final ────────────────────────────────────────
    print(f"  {C}━━━ OSINT RESUMEN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{N}")
    print(f"  {W}Fuentes:{N}       {', '.join(result.sources_used) or 'ninguna respondió'}")
    print(f"  {W}Subdominios:{N}   {len(result.subdomains)}")
    print(f"  {W}IPs:{N}           {len(result.ips)}")
    print(f"  {W}Puertos:{N}       {result.suggested_ports[:10]}")
    print(f"  {W}CVEs externos:{N} {len(result.cves_external)}")
    print(f"  {W}Emails:{N}        {len(result.emails)}")
    print(f"  {W}Tecnologías:{N}   {len(result.technologies)}")
    print(f"  {W}Hallazgos:{N}     {'SÍ — continuar scan' if result.has_findings else 'NO — objetivo sin exposición pública visible'}")
    print()

    # ── Guardar en disco ─────────────────────────────────────
    if outdir:
        osint_dir = Path(outdir) / "fase0_osint"
        osint_dir.mkdir(parents=True, exist_ok=True)
        (osint_dir / "osint_result.json").write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        osint_status(f"Resultado guardado en {osint_dir}", "ok")

    return result


# ════════════════════════════════════════════════════════════
#  STANDALONE
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="THOR OSINT Module")
    parser.add_argument("target",          nargs="?", help="IP o dominio")
    parser.add_argument("--setup-keys",    action="store_true", help="Configurar API keys")
    parser.add_argument("--show-keys",     action="store_true", help="Mostrar keys configuradas")
    args = parser.parse_args()

    keys = load_keys()

    if args.setup_keys or not keys:
        keys = setup_keys_interactive(keys)
        if not args.target:
            sys.exit(0)

    if args.show_keys:
        print(f"\n  {M}Keys configuradas:{N}")
        for k, v in keys.items():
            masked = v[:4] + "***" + v[-4:] if len(v) > 8 else "***"
            print(f"  {k:20} {G}{masked}{N}")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Resolver hostname si es dominio
    hostname = None
    target = args.target
    try:
        socket.inet_aton(target)
    except socket.error:
        hostname = target
        try:
            target = socket.gethostbyname(hostname)
        except Exception:
            pass

    result = run_osint(target, hostname=hostname, keys=keys)

    # Mostrar CVEs externos
    if result.cves_external:
        print(f"\n  {R}CVEs encontrados externamente:{N}")
        for c in result.cves_external:
            print(f"  {R}▶{N} {c['cve']} CVSS:{c['cvss']} [{c['source']}] — {c.get('summary','')[:80]}")
