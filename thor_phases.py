#!/usr/bin/env python3
# ============================================================
#  THOR PHASES MODULE
#  Contiene la clase ThorMemory y ThorAuto con todas las fases
# ============================================================

import subprocess, os, sys, json, re, socket, shutil, time
from datetime import datetime
from pathlib import Path

# Importar dependencias y utilidades desde el módulo externo
from thor_deps import (C, cmd, status, is_local, sanitize_target, sanitize_name,
                       print_banner, has_tool, check_and_install_deps)

# ── dependencia opcional: rich para dashboard ────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.markdown import Markdown
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False

# ════════════════════════════════════════════════════════════
#  SISTEMA DE MEMORIA (CORREGIDO)
# ════════════════════════════════════════════════════════════
MEMORY_FILE = Path("/var/log/thor_intel/.thor_memory.json")

class ThorMemory:
    def __init__(self):
        self.data = self._load()

    def _load(self):
        if MEMORY_FILE.exists():
            try:
                return json.loads(MEMORY_FILE.read_text())
            except Exception:
                pass
        return {
            "scan_count": 0,
            "recipes": {},
            "effective": {},
            "last_updated": ""
        }

    def _save(self):
        try:
            MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            MEMORY_FILE.write_text(json.dumps(self.data, indent=2))
        except Exception:
            pass

    def _svc_key(self, port_info):
        svc = port_info.get("service","unknown").lower()
        port = port_info.get("port",0)
        if "ssh" in svc: return "ssh"
        if "http" in svc: return "http"
        if "https" in svc or port in [443,8443]: return "https"
        if "smb" in svc or port in [139,445]: return "smb"
        if "mysql" in svc or port == 3306: return "mysql"
        if "ftp" in svc or port == 21: return "ftp"
        if "rdp" in svc or port == 3389: return "rdp"
        if "smtp" in svc or port in [25,587]: return "smtp"
        if "redis" in svc or port == 6379: return "redis"
        if "mongo" in svc or port == 27017: return "mongodb"
        if "mssql" in svc or port == 1433: return "mssql"
        if "pgsql" in svc or port == 5432: return "pgsql"
        return f"{svc}:{port}"

    def get_recipes(self, open_ports):
        recipes = []
        for p in open_ports:
            key = self._svc_key(p)
            if key in self.data["recipes"]:
                for r in self.data["recipes"][key]:
                    if r.get("effective",0) > r.get("ineffective",0):
                        recipes.append(r)
        return recipes

    def save_result(self, services, tool, cmd_args, cves_found, effective):
        self.data["scan_count"] = self.data.get("scan_count", 0) + 1
        self.data["last_updated"] = datetime.now().isoformat()
        cmd_hash = str(hash(cmd_args) & 0xFFFFFF)
        if cmd_hash not in self.data["effective"]:
            self.data["effective"][cmd_hash] = {
                "tool": tool, "cmd": cmd_args[:200],
                "hits": 0, "misses": 0, "cves_total": 0
            }
        if effective:
            self.data["effective"][cmd_hash]["hits"] += 1
            self.data["effective"][cmd_hash]["cves_total"] += cves_found
        else:
            self.data["effective"][cmd_hash]["misses"] += 1
        for p in services:
            key = self._svc_key(p)
            if key not in self.data["recipes"]:
                self.data["recipes"][key] = []
            existing = next((r for r in self.data["recipes"][key] if r["tool"] == tool), None)
            if existing:
                if effective:
                    existing["effective"] = existing.get("effective",0) + 1
                    existing["cves_total"] = existing.get("cves_total",0) + cves_found
                else:
                    existing["ineffective"] = existing.get("ineffective",0) + 1
            else:
                self.data["recipes"][key].append({
                    "tool": tool, "service": key,
                    "effective": 1 if effective else 0,
                    "ineffective": 0 if effective else 1,
                    "cves_total": cves_found,
                    "cmd_hint": cmd_args[:150]
                })
        self._save()

    def show_stats(self):
        print(f"\n  {C.C}━━━ MEMORIA THOR ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
        print(f"  {C.W}Scans totales:{C.N} {self.data.get('scan_count',0)}")
        print(f"  {C.W}Servicios aprendidos:{C.N} {len(self.data.get('recipes',{}))}")
        print(f"  {C.W}Última actualización:{C.N} {self.data.get('last_updated','nunca')}")
        if self.data.get("recipes"):
            print(f"\n  {C.W}Recetas efectivas por servicio:{C.N}")
            for svc, recipes in sorted(self.data["recipes"].items()):
                effective = [r for r in recipes if r.get("effective",0) > 0]
                if effective:
                    best = max(effective, key=lambda r: r.get("cves_total",0))
                    print(f"    {C.G}{svc:12}{C.N} → {best['tool']} "
                          f"({best.get('effective',0)} hits, "
                          f"{best.get('cves_total',0)} CVEs totales)")
        print()


# ════════════════════════════════════════════════════════════
#  CLASE PRINCIPAL ThorAuto (contiene todas las fases)
# ════════════════════════════════════════════════════════════
class ThorAuto:
    def __init__(self, target, hostname=None, forced_outdir=None):
        self.target      = target.strip()
        self.hostname    = hostname
        self.is_local    = is_local(self.target)
        self.start_time  = datetime.now()

        if forced_outdir:
            self.outdir = Path(forced_outdir)
            self.outdir.mkdir(parents=True, exist_ok=True)
            self.report_base = self.outdir.name
        else:
            self.report_base = self._build_report_name()
            self.target_safe = sanitize_name(self.target)
            self.outdir      = Path(f"/var/log/thor_intel/{self.report_base}")
            self.outdir.mkdir(parents=True, exist_ok=True)

        # Timing según contexto
        if self.is_local:
            self.nmap_timing = "-T4 --max-retries 2"
            self.to_ports    = 120
            self.to_services = 90
            self.to_vulns    = 300
            self.to_tool     = 120
        else:
            self.nmap_timing = "-T3 --max-retries 1"
            self.to_ports    = 300
            self.to_services = 180
            self.to_vulns    = 600
            self.to_tool     = 300

        # Resultados acumulados
        self.open_ports   = []
        self.cves         = []
        self.findings     = []
        self.credentials  = []
        self.tech_stack   = []
        self.os_guess     = ""
        self.risk_score   = 0
        self.risk_level   = "INFORMATIVO"
        self.tools_ran    = []
        self.osint_result = None

        # Detección de herramientas disponibles
        self.tools = {t: has_tool(t) for t in [
            "nmap","rustscan","nikto","gobuster","whatweb","sqlmap","hydra",
            "smbclient","enum4linux","nuclei","wpscan","sslscan",
            "msfconsole","curl","whois","dig","masscan"
        ]}

        # Nombres de archivos con base dominio_IP
        self.log_file    = self.outdir / "scan.log"
        self.report_md   = self.outdir / f"{self.report_base}.md"
        self.report_txt  = self.outdir / f"{self.report_base}.txt"
        self.report_json = self.outdir / f"{self.report_base}.json"
        self.report_html = self.outdir / f"{self.report_base}.html"

        # Sistema de memoria
        self.memory = ThorMemory()

    def _build_report_name(self):
        ip_safe = sanitize_name(self.target)
        ts = self.start_time.strftime("%Y%m%d_%H%M%S")
        if self.hostname:
            domain_clean = self.hostname.lower()
            domain_clean = re.sub(r'^www\.', '', domain_clean)
            domain_clean = sanitize_name(domain_clean)
            return f"{domain_clean}_{ip_safe}_{ts}"
        else:
            return f"{ip_safe}_{ts}"

    def log(self, msg):
        with open(self.log_file, "a") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")

    def save(self, filename, content):
        path = self.outdir / filename
        with open(path, "w") as f:
            f.write(content)
        return path

    # ================== FASE 0 – Recon pasivo + OSINT ==================
    def phase0_passive(self):
        status("FASE 0 — Recon pasivo + OSINT", "phase")
        d = self.outdir / "fase0_pasivo"
        d.mkdir(exist_ok=True)

        if self.tools["whois"]:
            status("whois lookup...", "info")
            out, _, _ = cmd(["whois", self.target], timeout=30)
            (d / "whois.txt").write_text(out)
            for line in out.splitlines():
                if re.match(r'^(org-name|OrgName|organisation|owner|country)', line, re.I):
                    status(line.strip(), "ok")

        status("DNS resolution...", "info")
        try:
            resolved = socket.gethostbyname(self.target)
            if resolved != self.target:
                status(f"Resolved: {self.target} → {resolved}", "ok")
                (d / "dns.txt").write_text(f"{self.target} → {resolved}\n")
        except:
            pass

        if self.tools["dig"]:
            out, _, _ = cmd(["dig", self.target, "ANY", "+short"], timeout=15)
            (d / "dig.txt").write_text(out)
            for line in out.splitlines()[:5]:
                if line.strip():
                    status(f"DNS: {line.strip()}", "ok")

        self.osint_result = None
        if not self.is_local:
            try:
                import importlib.util
                _script_dir = Path(__file__).parent
                _osint_path = _script_dir / "thor-osint.py"
                if not _osint_path.exists():
                    _osint_path = Path("thor-osint.py")

                if _osint_path.exists():
                    spec = importlib.util.spec_from_file_location(
                        "thor_osint", str(_osint_path))
                    thor_osint_mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(thor_osint_mod)

                    status("Iniciando OSINT multi-fuente...", "brain")
                    keys = thor_osint_mod.load_keys()
                    if not keys:
                        status("Sin API keys — solo fuentes gratuitas (crt.sh + DNS)", "info")
                        status(f"{C.D}Configurar: python3 thor-osint.py --setup-keys{C.N}", "info")

                    self.osint_result = thor_osint_mod.run_osint(
                        self.target,
                        hostname = self.hostname,
                        outdir   = str(self.outdir),
                        keys     = keys
                    )

                    self.tech_stack.extend(list(self.osint_result.technologies))
                    for c in self.osint_result.cves_external:
                        if c["cve"] not in [x["cve"] for x in self.cves]:
                            self.cves.append({
                                "cve":         c["cve"],
                                "cvss":        c.get("cvss","N/A"),
                                "exploit_url": "",
                                "db":          c.get("source","OSINT")
                            })
                            self.risk_score += 10
                            status(f"CVE externo [{c.get('source','OSINT')}]: {c['cve']} CVSS:{c.get('cvss','?')}", "fail")
                    for email in self.osint_result.emails:
                        self.findings.append({
                            "tool": "osint-whois", "port": 0,
                            "severity": "BAJO",
                            "detail": f"Email en registros públicos: {email}"
                        })
                    org = (self.osint_result.org_info.get("org","") or
                           self.osint_result.org_info.get("shodan_org",""))
                    if org:
                        status(f"Organización: {org}", "ok")
                    n_subs = len(self.osint_result.subdomains)
                    if n_subs > 0:
                        self.findings.append({
                            "tool": "osint-crtsh", "port": 0,
                            "severity": "BAJO",
                            "detail": f"{n_subs} subdominios/certs expuestos públicamente"
                        })
                        status(f"Subdominios encontrados: {n_subs}", "ok")
                    if "honeypot" in self.osint_result.shodan_data.get("tags",[]):
                        self.findings.append({
                            "tool": "osint-shodan", "port": 0,
                            "severity": "INFORMATIVO",
                            "detail": "Shodan clasifica este host como HONEYPOT"
                        })
                        status("ADVERTENCIA: Shodan marca este host como HONEYPOT", "fail")
                    all_osint_ports = set()
                    for ip_ports in self.osint_result.ports.values():
                        all_osint_ports.update(ip_ports)
                    if all_osint_ports:
                        status(f"Puertos conocidos por OSINT: {sorted(all_osint_ports)[:10]}", "brain")
                else:
                    status("thor-osint.py no encontrado — omitiendo OSINT", "info")
                    status(f"{C.D}Colocar thor-osint.py junto a thor-auto.py{C.N}", "info")
            except Exception as e:
                status(f"OSINT error: {e}", "fail")
                self.log(f"OSINT exception: {e}")
        else:
            status("Red local — OSINT externo omitido", "info")

        net_type = "LAN (red local)" if self.is_local else "Internet / red remota"
        status(f"Tipo de red: {net_type}", "ok")
        status(f"Timing nmap: {self.nmap_timing}", "ok")

    # ================== MACVLAN dinámico ==================
    def _setup_macvlan_interfaces(self, n_ifaces):
        import subprocess as sp
        r = sp.run(["ip","route","show","default"], capture_output=True, text=True)
        parent = ""
        for line in r.stdout.splitlines():
            m = re.search(r'dev\s+(\S+)', line)
            if m:
                parent = m.group(1)
                break
        if not parent:
            return []
        r2 = sp.run(["ip","-4","addr","show", parent], capture_output=True, text=True)
        parent_ip = ""; prefix = "24"
        for line in r2.stdout.splitlines():
            m = re.search(r'inet\s+([\d.]+)/(\d+)', line)
            if m:
                parent_ip = m.group(1)
                prefix    = m.group(2)
                break
        if not parent_ip:
            return []
        base = ".".join(parent_ip.split(".")[:3])
        gw_r = sp.run(["ip","route","show","default"], capture_output=True, text=True)
        gw = ""
        for line in gw_r.stdout.splitlines():
            m = re.search(r'via\s+([\d.]+)', line)
            if m:
                gw = m.group(1)
                break
        created = []
        ip_suffixes = [249,248,247,246][:n_ifaces]
        for i, suffix in enumerate(ip_suffixes):
            iface_name = f"thor{i}"
            virt_ip    = f"{base}.{suffix}/{prefix}"
            sp.run(["ip","link","del", iface_name], capture_output=True)
            mac = f"02:{i+1:02x}:{int(parent_ip.split('.')[2]):02x}:{suffix:02x}:aa:bb"
            r = sp.run(["ip","link","add", iface_name, "link", parent, "type", "macvlan", "mode", "bridge"],
                       capture_output=True)
            if r.returncode != 0:
                sp.run(["ip","link","add", iface_name, "link", parent, "type", "macvlan", "mode", "private"],
                       capture_output=True)
            sp.run(["ip","link","set", iface_name, "address", mac], capture_output=True)
            sp.run(["ip","addr","add", virt_ip, "dev", iface_name], capture_output=True)
            sp.run(["ip","link","set", iface_name, "up"], capture_output=True)
            if gw:
                sp.run(["ip","route","add","default","via", gw, "dev", iface_name, "metric", str(100+i)],
                       capture_output=True)
            r3 = sp.run(["ip","link","show", iface_name], capture_output=True, text=True)
            if "UP" in r3.stdout or "UNKNOWN" in r3.stdout:
                created.append(iface_name)
                status(f"Interface virtual: {iface_name} | MAC:{mac} | IP:{virt_ip}", "ok")
            else:
                status(f"No levantó {iface_name} — omitiendo", "fail")
        return created

    def _cleanup_macvlan(self, ifaces):
        import subprocess as sp
        for iface in ifaces:
            sp.run(["ip","route","del","default","dev", iface], capture_output=True)
            sp.run(["ip","link","del", iface], capture_output=True)

    # ================== FASE 1 – Port scan ==================
    def phase1_ports(self):
        status("FASE 1 — Port scan", "phase")
        d = self.outdir / "fase1_ports"
        d.mkdir(exist_ok=True)

        ports_file    = str(d / "ports.txt")
        ports_xml     = str(d / "ports.xml")
        rustscan_file = str(d / "rustscan.txt")

        ulimit = 5000 if self.is_local else 2000

        virt_ifaces = []
        if not self.is_local:
            n_ifaces = max(1, min(4, 65535 // 20000))
            status(f"Creando {n_ifaces} interfaces macvlan para scan distribuido...", "info")
            virt_ifaces = self._setup_macvlan_interfaces(n_ifaces)
            if virt_ifaces:
                status(f"Interfaces activas: {', '.join(virt_ifaces)}", "ok")

        rustscan_ports = []
        if self.tools.get("rustscan"):
            rs_strategies = [
                {"name": "RustScan full range", "args": ["--range", "1-65535", "--ulimit", str(ulimit), "-g"]},
                {"name": "RustScan critical ports", "args": ["--ports", "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017,9200,9300,6443,10250", "--ulimit", str(ulimit), "-g"]},
                {"name": "RustScan slow (anti-firewall)", "args": ["--range", "1-65535", "--ulimit", "500", "--timeout", "4000", "-g"]},
                {"name": "RustScan top-1000", "args": ["--range", "1-1000", "--ulimit", str(ulimit), "--tries", "3", "-g"]},
            ]
            for rs_strat in rs_strategies:
                if rustscan_ports:
                    break
                status(f"RustScan: {rs_strat['name']}", "info")
                rs_cmd = ["rustscan", "-a", self.target] + rs_strat["args"]
                self.log(f"RUSTSCAN: {' '.join(rs_cmd)}")
                rs_out, rs_err, rs_rc = cmd(rs_cmd, timeout=90)
                (Path(rustscan_file)).write_text(rs_out + rs_err)
                for line in rs_out.splitlines():
                    m = re.search(r'\[([0-9, ]+)\]', line)
                    if m:
                        for p in m.group(1).split(','):
                            p = p.strip()
                            if p.isdigit():
                                rustscan_ports.append(int(p))
                if rustscan_ports:
                    ports_str = ",".join(str(p) for p in sorted(rustscan_ports))
                    status(f"RustScan {rs_strat['name']} → {len(rustscan_ports)} puertos: {ports_str}", "ok")
                    self.log(f"RUSTSCAN ports: {ports_str}")
                    nmap_cmd = ["nmap", "-sS", "-Pn", *self.nmap_timing.split(), "-p", ports_str, "--open",
                                self.target, "-oN", ports_file, "-oX", ports_xml]
                    self.log(f"CMD: {' '.join(nmap_cmd)}")
                    cmd(nmap_cmd, timeout=self.to_ports)
                    if Path(ports_file).exists():
                        for line in Path(ports_file).read_text().splitlines():
                            m2 = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(.*)', line)
                            if m2:
                                port, proto, state, svc, ver = m2.groups()
                                if state in ("open","open|filtered"):
                                    self.open_ports.append({
                                        "port": int(port), "proto": proto,
                                        "state": state, "service": svc,
                                        "version": ver.strip()
                                    })
                    if not self.open_ports and rustscan_ports:
                        for p in rustscan_ports:
                            self.open_ports.append({"port": p, "proto": "tcp", "state": "open", "service": "unknown", "version": ""})
        else:
            status("RustScan no instalado — usando nmap directo", "info")

        if not self.open_ports:
            strategies = [
                {"name": "Normal SYN scan", "flags": ["-sS","-Pn",*self.nmap_timing.split(),"--open"], "ports": []},
                {"name": "TCP Connect (firewall bypass)", "flags": ["-sT","-Pn","-T3","--open"], "ports": []},
                {"name": "Puertos comunes forzados", "flags": ["-sS","-Pn","-T3","--open"], "ports": ["-p","21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017"]},
                {"name": "Stealth fragmentado", "flags": ["-sS","-Pn","-T2","-f","--data-length","32","--mtu","24","--open"], "ports": ["-p","80,443,22,21,25,3389,8080,8443"]},
                {"name": "Source port :53", "flags": ["-sS","-Pn","-T3","--open","--source-port","53"], "ports": ["-p","80,443,22,8080,8443,3389,3306,5432"]},
                {"name": "Source port :80", "flags": ["-sS","-Pn","-T3","--open","--source-port","80"], "ports": ["-p","443,8443,22,3389,1433,3306,5432,6379,27017"]},
                {"name": "Decoy scan", "flags": ["-sS","-Pn","-T3","--open","-D","RND:5"], "ports": ["-p","80,443,22,21,25,3389,8080,8443,3306"]},
                {"name": "TTL + padding", "flags": ["-sS","-Pn","-T2","--open","--ttl","128","--data-length","48","-f"], "ports": ["-p","80,443,22,3389,8080,8443"]},
                {"name": "UDP scan", "flags": ["-sU","-Pn","-T3","--open"], "ports": ["-p","53,67,68,69,111,123,137,138,161,500,514,1900,4500"]},
                {"name": "ACK scan", "flags": ["-sA","-Pn","-T3"], "ports": ["-p","80,443,22,25,3389"]},
                {"name": "Slow scan T1", "flags": ["-sS","-Pn","-T1","--open","--scan-delay","2s","--max-retries","1"], "ports": ["-p","80,443,22,8080,3389"]},
            ]
            for i, strat in enumerate(strategies):
                status(f"Intento {i+1}/{len(strategies)}: {strat['name']}", "info")
                self.log(f"ESTRATEGIA: {strat['name']}")
                nmap_cmd = ["nmap"] + strat["flags"] + strat["ports"] + [self.target, "-oN", ports_file, "-oX", ports_xml]
                self.log(f"CMD: {' '.join(nmap_cmd)}")
                cmd(nmap_cmd, timeout=self.to_ports)
                self.open_ports = []
                if Path(ports_file).exists():
                    for line in Path(ports_file).read_text().splitlines():
                        m = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(.*)', line)
                        if m:
                            port, proto, state, svc, ver = m.groups()
                            if state in ("open","open|filtered"):
                                self.open_ports.append({
                                    "port": int(port), "proto": proto,
                                    "state": state, "service": svc,
                                    "version": ver.strip()
                                })
                if self.open_ports:
                    status(f"Puertos encontrados con: {strat['name']}", "ok")
                    break
                if Path(ports_file).exists():
                    content = Path(ports_file).read_text()
                    if "filtered" in content:
                        status("Puertos filtrados — escalando técnica", "info")
                    elif "host seems down" in content.lower():
                        status("Host parece inactivo — forzando siguiente", "info")
                    else:
                        status("Sin respuesta — escalando evasión", "info")

        if virt_ifaces:
            self._cleanup_macvlan(virt_ifaces)
            status(f"Interfaces macvlan eliminadas", "info")

        if not self.open_ports:
            if self.osint_result and self.osint_result.has_findings:
                suggested = getattr(self.osint_result, 'suggested_ports', [80,443,8080,8443])
                status(f"Sin puertos por scan directo — OSINT encontró datos", "info")
                status(f"Puertos sugeridos por OSINT: {suggested[:10]}", "brain")
                for p in suggested[:10]:
                    self.open_ports.append({
                        "port": p, "proto": "tcp",
                        "state": "osint-suggested",
                        "service": "unknown", "version": ""
                    })
                status(f"Continuando scan con {len(self.open_ports)} puertos sugeridos por OSINT", "brain")
                return True
            else:
                status(f"Sin puertos detectados tras todas las técnicas", "fail")
                self.log("FASE1: sin puertos")
                return False
        self._print_ports()
        return True

    def _print_ports(self):
        status(f"Puertos abiertos: {len(self.open_ports)}", "ok")
        for p in self.open_ports:
            svc_info = f"{p['service']}"
            if p['version']:
                svc_info += f"  {C.D}{p['version']}{C.N}"
            status(f"  {C.G}{p['port']}/{p['proto']}{C.N}  {svc_info}", "ok")

    # ================== FASE 2 – Service fingerprint ==================
    def phase2_services(self):
        status("FASE 2 — Service fingerprint + OS detection", "phase")
        d = self.outdir / "fase2_services"
        d.mkdir(exist_ok=True)

        ports_str = ",".join(str(p["port"]) for p in self.open_ports)
        svc_file  = str(d / "services.txt")

        nmap_cmd = [
            "nmap", "-sS", "-Pn", *self.nmap_timing.split(), "-p", ports_str,
            "-sV", "-O", "--version-intensity", "7", self.target, "-oN", svc_file
        ]
        status(f"nmap service detection → {len(self.open_ports)} puertos", "info")
        out, err, rc = cmd(nmap_cmd, timeout=self.to_services)

        if Path(svc_file).exists():
            content = Path(svc_file).read_text()
            for line in content.splitlines():
                m = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
                if m:
                    port, proto, svc, ver = m.groups()
                    for p in self.open_ports:
                        if p["port"] == int(port):
                            p["service"] = svc
                            p["version"] = ver.strip()
                            if ver.strip():
                                self.tech_stack.append(f"{svc} {ver.strip()}")
            for line in content.splitlines():
                if re.match(r'^(OS details|Running|OS CPE):', line):
                    self.os_guess = line.split(":", 1)[1].strip()
                    status(f"OS: {self.os_guess}", "ok")
                    break

    # ================== FASE 3 – Motor de decisión ==================
    def phase3_decide(self):
        status("FASE 3 — Motor de decisión", "phase")
        plan = {
            "nse_scripts":  ["vuln", "exploit", "vulners"],
            "web_ports":    [], "smb": False, "ssh_ports": [], "ftp_ports": [],
            "db_ports":     [], "ssl_ports": [], "voip_ports": [], "rdp_ports": [],
            "smtp_ports":   [], "telnet_ports": [], "mongo_ports": [], "redis_ports": [],
        }
        if self.osint_result:
            for svc_key, svc_data in self.osint_result.services.items():
                port    = svc_data.get("port", 0)
                product = svc_data.get("product","").lower()
                known = [p["port"] for p in self.open_ports]
                if port and port not in known:
                    status(f"OSINT aportó puerto adicional: {port} ({svc_data.get('product','')})", "brain")
                    self.open_ports.append({
                        "port": port, "proto": svc_data.get("transport","tcp"),
                        "state": "osint-known", "service": svc_data.get("product","unknown"),
                        "version": svc_data.get("version","")
                    })
            if self.osint_result.subdomains and self.osint_result.certs:
                if 443 not in [p["port"] for p in self.open_ports]:
                    plan["web_ports"].append(443)
                    plan["ssl_ports"].append(443)
                    status("OSINT: certificados SSL detectados → agregando puerto 443 al plan", "brain")
                    plan["nse_scripts"] += ["ssl-heartbleed","ssl-cert","ssl-dh-params"]
            if "wordpress" in str(self.osint_result.technologies).lower():
                status("OSINT: WordPress detectado → WPScan activado", "brain")
                plan["wpscan_osint"] = True
            if "apache" in str(self.osint_result.technologies).lower() or "nginx" in str(self.osint_result.technologies).lower():
                plan["nse_scripts"] += ["http-shellshock","http-headers","http-methods"]
            asn = self.osint_result.org_info.get("asn","")
            org = self.osint_result.org_info.get("shodan_org","")
            if asn or org:
                status(f"Contexto: {org} | ASN: {asn}", "brain")

        for p in self.open_ports:
            port = p["port"]
            svc  = p["service"].lower()
            ver  = p["version"].lower()
            if port in [80,8080,8000,8888,3000] or "http" in svc:
                plan["web_ports"].append(port)
                plan["nse_scripts"] += ["http-enum","http-methods","http-shellshock","http-sql-injection"]
            if port in [443,8443,4443] or "https" in svc or "ssl" in ver or "tls" in ver:
                plan["web_ports"].append(port)
                plan["ssl_ports"].append(port)
                plan["nse_scripts"] += ["ssl-heartbleed","ssl-poodle","ssl-dh-params","ssl-cert"]
            if port in [139,445] or "smb" in svc or "netbios" in svc:
                plan["smb"] = True
                plan["nse_scripts"] += ["smb-vuln-ms17-010","smb-vuln-ms08-067","smb-enum-users","smb-enum-shares","smb-security-mode"]
            if port == 22 or "ssh" in svc:
                plan["ssh_ports"].append(port)
                plan["nse_scripts"] += ["ssh-auth-methods","ssh2-enum-algos"]
                if any(v in ver for v in ["openssh 4","openssh 5","openssh 6","openssh 7.1","openssh 7.2"]):
                    plan["nse_scripts"].append("sshv1")
                    self.findings.append({"tool": "decision-engine", "port": port, "severity": "ALTO", "detail": f"OpenSSH versión potencialmente vulnerable: {ver}"})
            if port == 21 or "ftp" in svc:
                plan["ftp_ports"].append(port)
                plan["nse_scripts"] += ["ftp-anon","ftp-bounce","ftp-syst","ftp-vuln-cve2010-4221"]
            if port == 3306 or "mysql" in svc:
                plan["db_ports"].append(("mysql", port))
                plan["nse_scripts"] += ["mysql-info","mysql-empty-password","mysql-databases"]
            if port == 5432 or "postgres" in svc:
                plan["db_ports"].append(("pgsql", port))
            if port == 1433 or "ms-sql" in svc or "mssql" in svc:
                plan["db_ports"].append(("mssql", port))
                plan["nse_scripts"] += ["ms-sql-info","ms-sql-config","ms-sql-empty-password"]
            if port == 6379 or "redis" in svc:
                plan["redis_ports"].append(port)
                plan["nse_scripts"].append("redis-info")
            if port == 27017 or "mongo" in svc:
                plan["mongo_ports"].append(port)
                plan["nse_scripts"] += ["mongodb-info","mongodb-databases"]
            if port == 23 or "telnet" in svc:
                plan["telnet_ports"].append(port)
                self.findings.append({"tool": "decision-engine", "port": port, "severity": "CRÍTICO", "detail": f"TELNET EXPUESTO en puerto {port} — protocolo sin cifrado, credenciales en texto plano"})
                self.risk_score += 40
            if port == 3389 or "rdp" in svc or "ms-wbt" in svc:
                plan["rdp_ports"].append(port)
                plan["nse_scripts"] += ["rdp-enum-encryption","rdp-vuln-ms12020"]
            if port in [25,587,465] or "smtp" in svc:
                plan["smtp_ports"].append(port)
                plan["nse_scripts"] += ["smtp-commands","smtp-open-relay","smtp-vuln-cve2010-4344"]
            if port in [5060,5061] or "sip" in svc:
                plan["voip_ports"].append(port)
                plan["nse_scripts"] += ["sip-methods","sip-enum-users"]
            if port in [21,22,23,25,110,135,139,445,1433,3306,3389,5432,6379,27017]:
                self.risk_score += 5

        plan["nse_scripts"] = list(dict.fromkeys(plan["nse_scripts"]))
        plan["web_ports"] = list(set(plan["web_ports"]))
        status(f"NSE scripts: {len(plan['nse_scripts'])} seleccionados", "brain")
        if plan["web_ports"]:
            status(f"Web audit: puertos {plan['web_ports']}", "brain")
        if plan["smb"]:
            status("SMB/AD recon activado", "brain")
        if plan["ssl_ports"]:
            status(f"SSL audit: puertos {plan['ssl_ports']}", "brain")
        if plan["db_ports"]:
            status(f"DB audit: {plan['db_ports']}", "brain")
        return plan

    # ================== FASE 4 – NSE, Vulscan y memoria ==================
    def phase4_nse(self, plan):
        status("FASE 4a — NSE vuln scan", "phase")
        d = self.outdir / "fase4_nse"
        d.mkdir(exist_ok=True)

        ports_str = ",".join(str(p["port"]) for p in self.open_ports)
        scripts = list(dict.fromkeys(plan["nse_scripts"]))
        vulns_file = str(d / "vulns.txt")
        vulns_xml  = str(d / "vulns.xml")

        nmap_cmd = [
            "nmap", "-sV", "-Pn", "--version-intensity", "7", *self.nmap_timing.split(),
            "-p", ports_str, "--script", ",".join(scripts),
            "--script-args", "vulners.mincvss=4.0",
            self.target, "-oN", vulns_file, "-oX", vulns_xml
        ]
        status(f"nmap NSE -sV → {len(scripts)} scripts", "info")
        self.log(f"CMD: {' '.join(nmap_cmd)}")
        cmd(nmap_cmd, timeout=self.to_vulns)

        cves_before = len(self.cves)
        if Path(vulns_file).exists():
            self._parse_nse_output(Path(vulns_file).read_text(), "nmap-NSE")
        cves_nse = len(self.cves) - cves_before
        status(f"NSE completado → {cves_nse} CVEs nuevos, {len(self.findings)} findings", "ok")
        self.tools_ran.append("nmap-NSE")
        self.memory.save_result(self.open_ports, "nmap-NSE", " ".join(nmap_cmd), cves_nse, cves_nse > 0)

        cves_before_vs = len(self.cves)
        self._phase4b_vulscan(ports_str, d)
        cves_vulscan = len(self.cves) - cves_before_vs
        total_found = cves_nse + cves_vulscan
        if total_found == 0:
            self._phase4c_memory_fallback(ports_str, d)

    def _vulscan_path(self):
        candidates = [
            "/usr/share/nmap/scripts/vulscan/vulscan.nse",
            "/usr/local/share/nmap/scripts/vulscan/vulscan.nse",
            Path.home() / ".nmap/scripts/vulscan/vulscan.nse",
        ]
        for p in candidates:
            if Path(p).exists():
                return str(p)
        out, _, _ = cmd(["find", "/usr", "/opt", "-name", "vulscan.nse", "-not", "-path", "*/proc/*"], timeout=10)
        for line in out.splitlines():
            if line.strip():
                return line.strip()
        return None

    def _phase4b_vulscan(self, ports_str, d):
        status("FASE 4b — Vulscan (multi-DB offline)", "phase")
        vulscan_nse = self._vulscan_path()
        if not vulscan_nse:
            status("Instalando vulscan...", "info")
            vulscan_nse = self._install_vulscan()
        if not vulscan_nse:
            status("Vulscan no disponible — omitiendo", "info")
            return
        status(f"vulscan.nse: {vulscan_nse}", "ok")
        vulscan_dir  = str(Path(vulscan_nse).parent)
        available_dbs = [
            db for db in ["cve.csv","exploitdb.csv","openvas.csv","osvdb.csv",
                          "scipvuldb.csv","securityfocus.csv","securitytracker.csv",
                          "xforce.csv"]
            if Path(vulscan_dir, db).exists()
        ]
        status(f"DBs: {len(available_dbs)} → {', '.join(d.replace('.csv','') for d in available_dbs)}", "ok")
        vulscan_file  = str(d / "vulscan.txt")
        exploit_file  = str(d / "vulscan_exploits.txt")
        db_list = ",".join(available_dbs) if available_dbs else ""
        script_args = "vulscanoutput=listid,vulners.mincvss=4.0"
        if db_list:
            script_args += f",vulscandb={db_list}"
        script_str = f"{vulscan_nse},vulners"
        nmap_cmd = [
            "nmap", "-sV", "-Pn", "--version-intensity", "9", *self.nmap_timing.split(),
            "-p", ports_str, "--script", script_str, "--script-args", script_args,
            self.target, "-oN", vulscan_file
        ]
        status(f"Vulscan+vulners -sV → {self.target}", "info")
        self.log(f"CMD: {' '.join(nmap_cmd)}")
        out, err, rc = cmd(nmap_cmd, timeout=600)
        if not Path(vulscan_file).exists():
            status("Vulscan sin output — reintentando sin vulners", "fail")
            nmap_cmd2 = ["nmap", "-sV", "-Pn", "-p", ports_str, "--script", vulscan_nse, "--script-args", "vulscanoutput=listid", self.target, "-oN", vulscan_file]
            cmd(nmap_cmd2, timeout=300)
        if not Path(vulscan_file).exists():
            status("Vulscan sin output tras reintentos", "fail")
            return

        content = Path(vulscan_file).read_text()
        exploits_found = []
        cves_vulscan   = []
        current_port   = 0
        current_db     = ""
        for line in content.splitlines():
            m_port = re.match(r'^(\d+)/(tcp|udp)', line)
            if m_port:
                current_port = int(m_port.group(1))
            if "VulDB"         in line: current_db = "VulDB"
            elif "MITRE CVE"   in line: current_db = "MITRE"
            elif "vulners"     in line: current_db = "vulners"
            elif "ExploitDB"   in line: current_db = "ExploitDB"
            elif "OpenVAS"     in line: current_db = "OpenVAS"
            elif "OSVDB"       in line: current_db = "OSVDB"
            elif "SecurityFocus" in line: current_db = "SecurityFocus"
            m_cve = re.search(r'(CVE-\d{4}-\d+)\s+([\d.]+)\s+(https?://\S+)', line)
            if m_cve:
                cve_id, score, link = m_cve.groups()
                has_exploit = "*EXPLOIT*" in line
                entry = {"cve": cve_id, "cvss": score, "link": link, "db": current_db, "port": current_port, "exploit": has_exploit}
                cves_vulscan.append(entry)
                if has_exploit:
                    exploits_found.append(entry)
                    self.risk_score += 30
                    status(f"{C.R}EXPLOIT: {cve_id} CVSS:{score} → {link}{C.N}", "fail")
                if cve_id not in [c["cve"] for c in self.cves]:
                    self.cves.append({"cve": cve_id, "cvss": score, "exploit_url": link if has_exploit else "", "db": current_db})
                    self.risk_score += 10
                elif has_exploit:
                    for c in self.cves:
                        if c["cve"] == cve_id:
                            c["exploit_url"] = link
            elif re.search(r'^\|\s+(CVE-\d{4}-\d+)\s*$', line):
                m2 = re.search(r'CVE-\d{4}-\d+', line)
                if m2:
                    cve_id = m2.group()
                    if cve_id not in [c["cve"] for c in self.cves]:
                        self.cves.append({"cve": cve_id, "cvss": "N/A", "exploit_url": "", "db": current_db})
                        self.risk_score += 8
        if exploits_found:
            lines_e = ["# EXPLOITS PÚBLICOS — VULSCAN\n"]
            for e in exploits_found:
                lines_e += [f"CVE: {e['cve']} | CVSS: {e['cvss']} | Puerto: {e['port']}", f"URL: {e['link']}", ""]
            Path(exploit_file).write_text("\n".join(lines_e))
            for e in exploits_found:
                self.findings.append({
                    "tool": "vulscan", "port": e["port"],
                    "severity": "CRÍTICO" if float(e["cvss"]) >= 7 else "ALTO",
                    "detail": f"{e['cve']} (CVSS {e['cvss']}) EXPLOIT: {e['link']}"
                })
        total_vs  = len(cves_vulscan)
        total_exp = len(exploits_found)
        status(f"Vulscan → {total_vs} CVEs, {C.R}{total_exp} exploits públicos{C.N}", "ok")
        self.memory.save_result(self.open_ports, "vulscan", " ".join(nmap_cmd), total_vs, total_vs > 0)
        self.tools_ran.append("vulscan")

    def _phase4c_memory_fallback(self, ports_str, d):
        status("FASE 4c — Fallback: consultando memoria de scans anteriores", "brain")
        recipes = self.memory.get_recipes(self.open_ports)
        if not recipes:
            status("Sin recetas en memoria para estos servicios — primera vez o sin historial", "info")
            status(f"{C.D}La memoria se irá construyendo con cada scan exitoso{C.N}", "info")
            return
        effective_recipes = [r for r in recipes if r.get("effective",0) > r.get("ineffective",0) and r.get("cves_total",0) > 0]
        if not effective_recipes:
            status("Recetas en memoria sin historial positivo suficiente", "info")
            return
        effective_recipes.sort(key=lambda r: r.get("cves_total",0), reverse=True)
        status(f"Memoria: {len(effective_recipes)} recetas efectivas encontradas", "brain")
        for r in effective_recipes[:3]:
            status(f"  {C.G}{r['service']}{C.N} → {r['tool']} ({r.get('effective',0)} hits, {r.get('cves_total',0)} CVEs históricos)", "brain")
        memory_file = str(d / "memory_fallback.txt")
        cves_before = len(self.cves)
        for recipe in effective_recipes[:2]:
            status(f"Reejecutando receta: {recipe['tool']} para {recipe['service']}", "brain")
            tool = recipe.get("tool", "")
            if "nmap" in tool.lower():
                hint = recipe.get("cmd_hint", "")
                scripts_hint = ""
                m = re.search(r'--script\s+(\S+)', hint)
                if m:
                    scripts_hint = m.group(1)
                if not scripts_hint:
                    scripts_hint = "vulners,vulscan/vulscan.nse"
                mem_cmd = [
                    "nmap", "-sV", "-Pn", "--version-intensity", "9",
                    "-p", ports_str, "--script", scripts_hint,
                    "--script-args", "vulners.mincvss=3.0,vulscanoutput=listid",
                    self.target, "-oN", memory_file
                ]
                self.log(f"MEMORIA CMD: {' '.join(mem_cmd)}")
                cmd(mem_cmd, timeout=self.to_vulns)
                if Path(memory_file).exists():
                    self._parse_nse_output(Path(memory_file).read_text(), f"memoria:{recipe['service']}")
        cves_memory = len(self.cves) - cves_before
        if cves_memory > 0:
            status(f"Memoria efectiva → {cves_memory} CVEs adicionales encontrados", "ok")
            self.memory.save_result(self.open_ports, "memoria-fallback", "memory_fallback", cves_memory, True)
        else:
            status("Memoria no encontró CVEs adicionales en este scan", "info")
            self.memory.save_result(self.open_ports, "memoria-fallback", "memory_fallback", 0, False)

    def _install_vulscan(self):
        if not has_tool("git"):
            return None
        install_path = "/usr/share/nmap/scripts/vulscan"
        if not Path(install_path).exists():
            status("Clonando vulscan desde GitHub...", "info")
            out, err, rc = cmd(["git", "clone", "--depth", "1", "https://github.com/scipag/vulscan", install_path], timeout=120)
            if rc == 0:
                cmd(["nmap", "--script-updatedb"], timeout=30)
                nse = f"{install_path}/vulscan.nse"
                if Path(nse).exists():
                    status("Vulscan instalado correctamente", "ok")
                    return nse
        return None

    def _parse_nse_output(self, content, tool_name):
        for cve in re.findall(r'CVE-\d{4}-\d+', content):
            cvss = "N/A"
            for line in content.splitlines():
                if cve in line:
                    m = re.search(r'(\d+\.\d+)', line)
                    if m:
                        score = float(m.group(1))
                        if 0 < score <= 10:
                            cvss = str(score)
                            break
            if cve not in [c["cve"] for c in self.cves]:
                self.cves.append({"cve": cve, "cvss": cvss, "exploit_url": "", "db": tool_name})
                self.risk_score += 10
                status(f"CVE: {cve} (CVSS: {cvss})", "fail")
        for line in content.splitlines():
            if re.search(r'VULNERABLE|State: VULNERABLE|likely VULNERABLE', line):
                self.findings.append({"tool": tool_name, "port": 0, "severity": "ALTO", "detail": line.strip()})
                self.risk_score += 20
                status(f"VULN: {line.strip()}", "fail")

    # ================== FASE 5 – Scans específicos ==================
    def phase5_targeted(self, plan):
        status("FASE 5 — Scans específicos por servicio", "phase")
        d = self.outdir / "fase5_targeted"
        d.mkdir(exist_ok=True)

        for port in plan["web_ports"]:
            proto = "https" if port in [443,8443,4443] else "http"
            url   = f"{proto}://{self.target}:{port}"
            if self.tools["whatweb"]:
                status(f"WhatWeb → {url}", "info")
                out, _, _ = cmd(["whatweb", "-a", "3", url], timeout=self.to_tool)
                (d / f"whatweb_{port}.txt").write_text(out)
                for tech in re.findall(r'(WordPress|Joomla|Drupal|Apache|nginx|IIS|PHP|ASP\.NET|jQuery|Bootstrap|Python|Ruby|Java|Laravel|Django)[^,\]]*', out, re.I):
                    clean = tech.strip()
                    if clean and clean not in self.tech_stack:
                        self.tech_stack.append(clean)
                self.tools_ran.append(f"whatweb:{port}")
            if self.tools["nikto"]:
                status(f"Nikto → {url}", "info")
                out, _, _ = cmd(["nikto", "-h", url, "-Format", "txt", "-nointeractive"], timeout=self.to_tool)
                (d / f"nikto_{port}.txt").write_text(out)
                for line in out.splitlines():
                    if line.startswith("+"):
                        sev = "ALTO" if "CVE" in line or "injection" in line.lower() else "MEDIO"
                        cve_m = re.search(r'CVE-\d{4}-\d+', line)
                        self.findings.append({"tool": f"nikto:{port}", "port": port, "severity": sev, "detail": line.strip()})
                        if cve_m:
                            cve = cve_m.group()
                            if cve not in [c["cve"] for c in self.cves]:
                                self.cves.append({"cve": cve, "cvss": "N/A"})
                        self.risk_score += 3
                self.tools_ran.append(f"nikto:{port}")
            if self.tools["gobuster"]:
                wlist = "/usr/share/wordlists/dirb/common.txt"
                if not Path(wlist).exists():
                    wlist = "/usr/share/dirb/wordlists/common.txt"
                if Path(wlist).exists():
                    status(f"Gobuster → {url}", "info")
                    out, _, _ = cmd(["gobuster", "dir", "-u", url, "-w", wlist, "-t", "20", "-q", "--no-error"], timeout=self.to_tool)
                    (d / f"gobuster_{port}.txt").write_text(out)
                    hits = [l for l in out.splitlines() if "Status:" in l]
                    if hits:
                        status(f"Gobuster: {len(hits)} paths encontrados", "ok")
                    self.tools_ran.append(f"gobuster:{port}")
            if self.tools["nuclei"]:
                status(f"Nuclei → {url}", "info")
                out, _, _ = cmd(["nuclei", "-u", url, "-severity", "critical,high,medium", "-silent"], timeout=self.to_tool)
                (d / f"nuclei_{port}.txt").write_text(out)
                for line in out.splitlines():
                    if line.strip():
                        sev = "CRÍTICO" if "critical" in line.lower() else ("ALTO" if "high" in line.lower() else "MEDIO")
                        self.findings.append({"tool": f"nuclei:{port}", "port": port, "severity": sev, "detail": line.strip()})
                        self.risk_score += {"CRÍTICO":25,"ALTO":15,"MEDIO":8}.get(sev,5)
                self.tools_ran.append(f"nuclei:{port}")
            if self.tools["wpscan"]:
                ww_file = d / f"whatweb_{port}.txt"
                if ww_file.exists() and "wordpress" in ww_file.read_text().lower():
                    status(f"WordPress detectado → WPScan", "info")
                    out, _, _ = cmd(["wpscan", "--url", url, "--no-banner", "--enumerate", "vp,u"], timeout=self.to_tool)
                    (d / f"wpscan_{port}.txt").write_text(out)
                    for line in out.splitlines():
                        if "[!" in line or "vulnerability" in line.lower():
                            self.findings.append({"tool": f"wpscan:{port}", "port": port, "severity": "ALTO", "detail": line.strip()})
                    self.tools_ran.append(f"wpscan:{port}")
            if port in plan["ssl_ports"] and self.tools["sslscan"]:
                status(f"SSLScan → {self.target}:{port}", "info")
                out, _, _ = cmd(["sslscan", f"{self.target}:{port}"], timeout=60)
                (d / f"sslscan_{port}.txt").write_text(out)
                for line in out.splitlines():
                    if any(w in line for w in ["SSLv2","SSLv3","TLSv1.0","VULNERABLE","INSECURE"]):
                        self.findings.append({"tool": f"sslscan:{port}", "port": port, "severity": "MEDIO", "detail": line.strip()})
                self.tools_ran.append(f"sslscan:{port}")

        if plan["smb"]:
            if self.tools["enum4linux"]:
                status(f"Enum4linux → {self.target}", "info")
                out, _, _ = cmd(["enum4linux", "-a", self.target], timeout=120)
                (d / "enum4linux.txt").write_text(out)
                for line in out.splitlines():
                    if re.search(r'user:\[|Account:', line):
                        self.findings.append({"tool": "enum4linux", "port": 445, "severity": "MEDIO", "detail": f"Usuario SMB: {line.strip()}"})
                self.tools_ran.append("enum4linux")
            if self.tools["smbclient"]:
                status(f"SMBClient shares → {self.target}", "info")
                out, _, _ = cmd(["smbclient", "-L", f"//{self.target}", "-N"], timeout=30)
                (d / "smb_shares.txt").write_text(out)
                for line in out.splitlines():
                    if "Disk" in line or "IPC" in line:
                        self.findings.append({"tool": "smbclient", "port": 445, "severity": "BAJO", "detail": f"Share SMB: {line.strip()}"})
                self.tools_ran.append("smbclient")

        for port in plan["ftp_ports"]:
            status(f"FTP anon check → {self.target}:{port}", "info")
            out, _, _ = cmd(["nmap", "-p", str(port), "--script", "ftp-anon", self.target, "-oN", str(d / f"ftp_{port}.txt")], timeout=30)
            if "Anonymous FTP login allowed" in (d / f"ftp_{port}.txt").read_text():
                self.findings.append({"tool": "nmap-ftp", "port": port, "severity": "ALTO", "detail": f"FTP login anónimo permitido en puerto {port}"})
                self.risk_score += 20
                status("FTP anónimo permitido — ALTO riesgo", "fail")

        for db_type, port in plan["db_ports"]:
            scripts_map = {"mysql": "mysql-info,mysql-empty-password", "mssql": "ms-sql-info,ms-sql-empty-password", "pgsql": "pgsql-brute"}
            scripts = scripts_map.get(db_type, "")
            if scripts:
                status(f"{db_type.upper()} scan → {self.target}:{port}", "info")
                out, _, _ = cmd(["nmap", "-p", str(port), "--script", scripts, self.target, "-oN", str(d / f"{db_type}_{port}.txt")], timeout=60)
                content = (d / f"{db_type}_{port}.txt").read_text()
                if "empty-password" in content.lower() or "login successful" in content.lower():
                    self.findings.append({"tool": f"nmap-{db_type}", "port": port, "severity": "CRÍTICO", "detail": f"Base de datos {db_type.upper()}:{port} con credenciales vacías o default"})
                    self.risk_score += 40

        for port in plan["redis_ports"]:
            status(f"Redis check → {self.target}:{port}", "info")
            out, _, _ = cmd(["nmap", "-p", str(port), "--script", "redis-info", self.target, "-oN", str(d / f"redis_{port}.txt")], timeout=30)
            content = (d / f"redis_{port}.txt").read_text()
            if "redis_version" in content.lower():
                self.findings.append({"tool": "nmap-redis", "port": port, "severity": "CRÍTICO", "detail": f"Redis en puerto {port} accesible sin autenticación"})
                self.risk_score += 40
                status("Redis sin autenticación — CRÍTICO", "fail")

    # ================== FASE 6 – Risk scoring ==================
    def phase6_score(self):
        status("FASE 6 — Risk scoring", "phase")
        self.risk_score += len(self.cves) * 10
        for f in self.findings:
            self.risk_score += {"CRÍTICO":25,"ALTO":15,"MEDIO":8,"BAJO":3}.get(f["severity"],0)
        if   self.risk_score >= 150: self.risk_level = "CRÍTICO"
        elif self.risk_score >= 80:  self.risk_level = "ALTO"
        elif self.risk_score >= 40:  self.risk_level = "MEDIO"
        elif self.risk_score >= 10:  self.risk_level = "BAJO"
        else:                         self.risk_level = "INFORMATIVO"
        colors = {"CRÍTICO":C.R, "ALTO":C.Y, "MEDIO":C.C, "BAJO":C.G, "INFORMATIVO":C.D}
        color = colors.get(self.risk_level, C.D)
        print(f"\n  {C.W}RISK SCORE:{C.N} {color}{self.risk_level}{C.N} │ Score: {C.W}{self.risk_score}{C.N}")
        bar_len = min(20, self.risk_score // 10)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  {color}{bar}{C.N}\n")

    # ================== FASE 7 – Reportes ==================
    def phase7_report(self):
        status("FASE 7 — Generando reporte ejecutivo", "phase")
        elapsed = str(datetime.now() - self.start_time).split(".")[0]
        osint_summary = {}
        if self.osint_result:
            osint_summary = {
                "sources_used":    self.osint_result.sources_used,
                "subdomains":      sorted(self.osint_result.subdomains)[:30],
                "ips":             sorted(self.osint_result.ips),
                "emails":          sorted(self.osint_result.emails),
                "technologies":    sorted(self.osint_result.technologies),
                "cves_external":   self.osint_result.cves_external,
                "ports_osint":     self.osint_result.ports,
                "org_info":        self.osint_result.org_info,
                "has_findings":    self.osint_result.has_findings,
                "certs_count":     len(self.osint_result.certs),
            }
        data = {
            "target":      self.target,
            "hostname":    self.hostname,
            "date":        self.start_time.isoformat(),
            "elapsed":     elapsed,
            "os_guess":    self.os_guess,
            "risk_level":  self.risk_level,
            "risk_score":  self.risk_score,
            "open_ports":  self.open_ports,
            "tech_stack":  self.tech_stack,
            "cves":        self.cves,
            "findings":    self.findings,
            "credentials": self.credentials,
            "tools_ran":   self.tools_ran,
            "osint":       osint_summary,
            "outdir":      str(self.outdir)
        }
        self.report_json.write_text(json.dumps(data, indent=2, ensure_ascii=False))

        # Generar markdown y txt (simplificado pero completo)
        lines = []
        lines.append(f"# THOR AUTO — Reporte Ejecutivo\n")
        lines.append(f"| Campo | Valor |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Target** | `{self.target}` |")
        if self.hostname: lines.append(f"| **Hostname** | `{self.hostname}` |")
        lines.append(f"| **Fecha** | {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} |")
        lines.append(f"| **Duración** | {elapsed} |")
        lines.append(f"| **OS** | {self.os_guess or 'No detectado'} |")
        lines.append(f"| **Risk Level** | **{self.risk_level}** |")
        lines.append(f"| **Risk Score** | {self.risk_score} pts |")
        lines.append(f"| **CVEs** | {len(self.cves)} |")
        lines.append(f"| **Findings** | {len(self.findings)} |")
        if osint_summary:
            lines.append(f"| **Fuentes OSINT** | {', '.join(osint_summary.get('sources_used',[]))} |")
            lines.append(f"| **Subdominios** | {len(osint_summary.get('subdomains',[]))} |")
        lines.append("")
        if self.osint_result and self.osint_result.has_findings:
            lines.append(f"## Inteligencia OSINT\n")
            if self.osint_result.org_info:
                org  = self.osint_result.org_info.get("org","") or self.osint_result.org_info.get("shodan_org","")
                asn  = self.osint_result.org_info.get("asn","")
                isp  = self.osint_result.org_info.get("shodan_isp","")
                city = self.osint_result.org_info.get("shodan_city","")
                country = self.osint_result.org_info.get("shodan_country","")
                if org:   lines.append(f"- **Organización:** {org}")
                if asn:   lines.append(f"- **ASN:** {asn}")
                if isp:   lines.append(f"- **ISP:** {isp}")
                if city:  lines.append(f"- **Ubicación:** {city}, {country}")
                lines.append("")
            if self.osint_result.subdomains:
                lines.append(f"### Subdominios / Certificados ({len(self.osint_result.subdomains)})\n")
                for sub in sorted(self.osint_result.subdomains)[:20]:
                    lines.append(f"- `{sub}`")
                if len(self.osint_result.subdomains) > 20:
                    lines.append(f"- _... y {len(self.osint_result.subdomains)-20} más_")
                lines.append("")
            if len(self.osint_result.ips) > 1:
                lines.append(f"### IPs Asociadas\n")
                for ip in sorted(self.osint_result.ips):
                    lines.append(f"- `{ip}`")
                lines.append("")
            if self.osint_result.emails:
                lines.append(f"### Emails Expuestos\n")
                for email in sorted(self.osint_result.emails):
                    lines.append(f"- `{email}`")
                lines.append("")
            all_osint_ports = set()
            for ip_ports in self.osint_result.ports.values():
                all_osint_ports.update(ip_ports)
            if all_osint_ports:
                lines.append(f"### Puertos Visibles Externamente (Shodan/Censys)\n")
                lines.append(f"`{', '.join(str(p) for p in sorted(all_osint_ports))}`\n")
            if self.osint_result.cves_external:
                lines.append(f"### CVEs Detectados por OSINT ({len(self.osint_result.cves_external)})\n")
                for c in self.osint_result.cves_external:
                    cid  = c["cve"]
                    cvss = c.get("cvss","N/A")
                    src  = c.get("source","")
                    summ = c.get("summary","")[:100]
                    lines.append(f"#### {cid} (CVSS: {cvss}) [{src}]")
                    if summ: lines.append(f"{summ}")
                    lines.append(f"- **NVD:** https://nvd.nist.gov/vuln/detail/{cid}")
                    lines.append(f"- **MITRE:** https://cve.mitre.org/cgi-bin/cvename.cgi?name={cid}\n")
        lines.append(f"## Puertos Abiertos\n")
        lines.append(f"| Puerto | Protocolo | Servicio | Versión |")
        lines.append(f"|--------|-----------|----------|---------|")
        for p in self.open_ports:
            lines.append(f"| {p['port']} | {p['proto']} | {p['service']} | {p['version']} |")
        lines.append("")
        if self.tech_stack:
            lines.append(f"## Stack Tecnológico Detectado\n")
            for t in sorted(set(self.tech_stack)):
                lines.append(f"- {t}")
            lines.append("")
        if self.cves:
            exploits_cves = [c for c in self.cves if c.get("exploit_url")]
            normal_cves   = [c for c in self.cves if not c.get("exploit_url")]
            lines.append(f"## CVEs Encontrados ({len(self.cves)})")
            if exploits_cves:
                lines.append(f"> ⚠️ **{len(exploits_cves)} con exploit público disponible**\n")
            for c in exploits_cves:
                cve  = c["cve"]
                cvss = c.get("cvss", "N/A")
                db   = c.get("db", "")
                lines.append(f"### 🔴 {cve} — CRÍTICO (CVSS: {cvss}) `EXPLOIT PÚBLICO`\n")
                lines.append(f"| Campo | URL |")
                lines.append(f"|-------|-----|")
                lines.append(f"| **NVD** | https://nvd.nist.gov/vuln/detail/{cve} |")
                lines.append(f"| **MITRE** | https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve} |")
                lines.append(f"| **ExploitDB** | https://www.exploit-db.com/search?cve={cve[4:]} |")
                if c.get("exploit_url"): lines.append(f"| **Exploit directo** | {c['exploit_url']} |")
                if db: lines.append(f"| **Detectado por** | {db} |")
                lines.append("")
            for c in normal_cves:
                cve  = c["cve"]
                cvss = c.get("cvss", "N/A")
                db   = c.get("db", "")
                lines.append(f"### {cve} (CVSS: {cvss})\n")
                lines.append(f"- **NVD:** https://nvd.nist.gov/vuln/detail/{cve}")
                lines.append(f"- **MITRE:** https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")
                lines.append(f"- **ExploitDB:** https://www.exploit-db.com/search?cve={cve[4:]}")
                if db: lines.append(f"- **DB:** {db}")
                lines.append("")
        for sev in ["CRÍTICO","ALTO","MEDIO","BAJO"]:
            hits = [f for f in self.findings if f["severity"] == sev]
            if hits:
                lines.append(f"## Hallazgos — {sev} ({len(hits)})\n")
                for h in hits:
                    lines.append(f"- **[{h['tool']}]** Puerto {h['port']}: {h['detail']}")
                lines.append("")
        lines.append(f"## Remediaciones Sugeridas\n")
        remed = self._generate_remediations()
        lines.extend(remed)
        lines.append(f"\n---\n")
        lines.append(f"**Herramientas ejecutadas:** {', '.join(self.tools_ran)}")
        lines.append(f"**Directorio:** `{self.outdir}`")
        lines.append(f"\n_Generado por THOR Auto v1.0 — {datetime.now()}_")
        md_content = "\n".join(lines)
        self.report_md.write_text(md_content)
        txt = re.sub(r'\*\*|__|\*|_|`|#{1,6} ', '', md_content)
        self.report_txt.write_text(txt)
        status(f"Reporte MD:   {self.report_md}", "ok")
        status(f"Reporte TXT:  {self.report_txt}", "ok")
        status(f"Reporte JSON: {self.report_json}", "ok")
        try:
            html_path = self._generate_html_report()
            status(f"Reporte HTML: {html_path}", "ok")
        except Exception as e:
            status(f"HTML generation error: {e}", "fail")
            self.log(f"HTML error: {e}")

    def _generate_remediations(self):
        lines = []
        for c in self.cves:
            cve = c["cve"]
            if "2017-0144" in cve or "2017-0145" in cve:
                lines.append(f"### EternalBlue ({cve})")
                lines.append("```bash")
                lines.append("# Verificar parche MS17-010 en Windows")
                lines.append("wmic qfe get hotfixid | findstr KB4012212")
                lines.append("# Aplicar parche")
                lines.append("# https://support.microsoft.com/kb/4012212")
                lines.append("# Deshabilitar SMBv1 (PowerShell)")
                lines.append("Set-SmbServerConfiguration -EnableSMB1Protocol $false")
                lines.append("```\n")
            elif "2014-0160" in cve:
                lines.append(f"### Heartbleed ({cve})")
                lines.append("```bash")
                lines.append("# Actualizar OpenSSL")
                lines.append("apt-get update && apt-get install openssl libssl-dev")
                lines.append("# Verificar versión (debe ser >= 1.0.1g)")
                lines.append("openssl version")
                lines.append("# Revocar y reemitir certificados SSL después del parche")
                lines.append("```\n")
        has_telnet   = any("TELNET"  in f["detail"] for f in self.findings)
        has_ftp_anon = any("anón"    in f["detail"].lower() or "anonymous" in f["detail"].lower() for f in self.findings)
        has_redis    = any("redis"   in f["detail"].lower() for f in self.findings)
        has_smb      = any("smb"     in f["tool"].lower() or "enum4linux" in f["tool"] for f in self.findings)
        has_ssl_weak = any("SSLv"    in f["detail"] or "TLSv1.0" in f["detail"] for f in self.findings)
        if has_telnet:
            lines.append("### Deshabilitar Telnet")
            lines.append("```bash")
            lines.append("systemctl stop telnet.socket && systemctl disable telnet.socket")
            lines.append("apt-get install openssh-server")
            lines.append("systemctl enable ssh && systemctl start ssh")
            lines.append("iptables -A INPUT -p tcp --dport 23 -j DROP")
            lines.append("```\n")
        if has_ftp_anon:
            lines.append("### Deshabilitar FTP Anónimo")
            lines.append("```bash")
            lines.append("# vsftpd: editar /etc/vsftpd.conf")
            lines.append("sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf")
            lines.append("systemctl restart vsftpd")
            lines.append("grep anonymous_enable /etc/vsftpd.conf")
            lines.append("```\n")
        if has_redis:
            lines.append("### Asegurar Redis")
            lines.append("```bash")
            lines.append("# Agregar contraseña en /etc/redis/redis.conf")
            lines.append("echo 'requirepass TuPasswordSegura123!' >> /etc/redis/redis.conf")
            lines.append("# Bind solo a localhost si no necesita acceso externo")
            lines.append("sed -i 's/bind 0.0.0.0/bind 127.0.0.1/' /etc/redis/redis.conf")
            lines.append("systemctl restart redis")
            lines.append("```\n")
        if has_ssl_weak:
            lines.append("### Deshabilitar SSL/TLS débil (nginx)")
            lines.append("```nginx")
            lines.append("ssl_protocols TLSv1.2 TLSv1.3;")
            lines.append("ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;")
            lines.append("ssl_prefer_server_ciphers on;")
            lines.append("```")
            lines.append("```bash")
            lines.append("# Apache: /etc/apache2/mods-enabled/ssl.conf")
            lines.append("SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1")
            lines.append("SSLCipherSuite HIGH:!aNULL:!MD5:!3DES")
            lines.append("```\n")
        if not lines:
            lines.append("_Sin remediaciones específicas identificadas para los hallazgos actuales._\n")
            lines.append("**Recomendación general:** mantener todos los servicios actualizados")
            lines.append("y aplicar el principio de mínimo privilegio.")
        return lines

    def _generate_html_report(self):
        import html as html_escape
        risk_colors = {"CRÍTICO":"#e74c3c","ALTO":"#e67e22","MEDIO":"#f39c12","BAJO":"#27ae60","INFORMATIVO":"#7f8c8d"}
        risk_color = risk_colors.get(self.risk_level, "#7f8c8d")
        exploit_cves = [c for c in self.cves if c.get("exploit_url")]
        normal_cves  = [c for c in self.cves if not c.get("exploit_url")]
        def cvss_badge(cvss):
            try:
                v = float(cvss)
                if v >= 9:   return '<span class="badge critical">CRÍTICO</span>'
                if v >= 7:   return '<span class="badge high">ALTO</span>'
                if v >= 4:   return '<span class="badge medium">MEDIO</span>'
                return        '<span class="badge low">BAJO</span>'
            except:
                return '<span class="badge info">N/A</span>'
        def sev_badge(sev):
            cls = {"CRÍTICO":"critical","ALTO":"high","MEDIO":"medium","BAJO":"low"}.get(sev,"info")
            return f'<span class="badge {cls}">{sev}</span>'
        ports_rows = ""
        for p in self.open_ports:
            ports_rows += f"<tr><td><strong>{p['port']}</strong></td><td>{p['proto'].upper()}</td><td>{p['service']}</td><td class='version'>{p.get('version','')}</td></tr>"
        cves_html = ""
        for c in exploit_cves + normal_cves:
            exp_url = c.get("exploit_url","")
            db = c.get("db","")
            exploit_tag = '<span class="exploit-badge">⚠ EXPLOIT PÚBLICO</span>' if exp_url else ""
            cves_html += f"""
            <div class="cve-card {'cve-exploit' if exp_url else ''}">
              <div class="cve-header">
                <span class="cve-id">{c['cve']}</span>
                {cvss_badge(c.get('cvss','N/A'))}
                {exploit_tag}
                <span class="cve-db">{db}</span>
              </div>
              <div class="cve-links">
                <a href="https://nvd.nist.gov/vuln/detail/{c['cve']}" target="_blank">NVD</a>
                <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={c['cve']}" target="_blank">MITRE</a>
                <a href="https://www.exploit-db.com/search?cve={c['cve'][4:]}" target="_blank">ExploitDB</a>
                {f'<a href="{exp_url}" target="_blank" class="exploit-link">Exploit directo →</a>' if exp_url else ''}
              </div>
            </div>"""
        findings_html = ""
        for sev in ["CRÍTICO","ALTO","MEDIO","BAJO"]:
            hits = [f for f in self.findings if f["severity"] == sev]
            if not hits: continue
            findings_html += f'<h3>{sev_badge(sev)} {sev} ({len(hits)})</h3><ul>'
            for h in hits:
                findings_html += f'<li><code>[{h["tool"]}]</code> Puerto {h["port"]}: {h["detail"]}</li>'
            findings_html += "</ul>"
        tech_pills = "".join(f'<span class="tech-pill">{t}</span>' for t in sorted(set(self.tech_stack)))
        ts = self.start_time.strftime("%Y-%m-%d %H:%M:%S")
        elapsed = str(datetime.now() - self.start_time).split(".")[0]
        display_target = f"{self.hostname} ({self.target})" if self.hostname else self.target

        # Desglose del score
        score_items = []
        critical_ports = [p for p in self.open_ports if p["port"] in [21,22,23,25,110,135,139,445,1433,3306,3389,5432,6379,27017]]
        if critical_ports:
            pts = len(critical_ports) * 5
            score_items.append((f"Puertos críticos expuestos ({len(critical_ports)})", pts, "#d29922"))
        if self.cves:
            pts = len(self.cves) * 10
            score_items.append((f"CVEs detectados ({len(self.cves)} × 10pts)", pts, "#f85149"))
        exploit_count = len([c for c in self.cves if c.get("exploit_url")])
        if exploit_count:
            score_items.append((f"CVEs con exploit público ({exploit_count})", "⚠ +riesgo real", "#f85149"))
        sev_counts = {"CRÍTICO":0,"ALTO":0,"MEDIO":0,"BAJO":0}
        for f in self.findings:
            sev_counts[f["severity"]] += 1
        sev_pts_map = {"CRÍTICO":25,"ALTO":15,"MEDIO":8,"BAJO":3}
        for sev in ["CRÍTICO","ALTO","MEDIO","BAJO"]:
            if sev_counts[sev]:
                pts = sev_counts[sev] * sev_pts_map[sev]
                color = {"CRÍTICO":"#f85149","ALTO":"#d29922","MEDIO":"#e3b341","BAJO":"#3fb950"}[sev]
                score_items.append((f"Findings {sev} ({sev_counts[sev]} × {sev_pts_map[sev]}pts)", pts, color))
        if self.credentials:
            score_items.append(("Credenciales obtenidas", "+CRÍTICO", "#f85149"))
        score_breakdown_html = ""
        if score_items:
            for label, pts, color in score_items:
                pts_str = str(pts) if isinstance(pts, int) else pts
                score_breakdown_html += f"""
                <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--border)">
                  <span style="font-size:12px;color:var(--text)">{label}</span>
                  <span style="font-weight:700;color:{color};font-size:13px">{pts_str}</span>
                </div>"""
            score_breakdown_html += f"""
            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;margin-top:4px">
              <span style="font-size:13px;font-weight:600;color:var(--text)">TOTAL</span>
              <span style="font-weight:700;color:{risk_color};font-size:16px">{self.risk_score} pts</span>
            </div>"""
        else:
            score_breakdown_html = '<div style="color:var(--text2);font-size:12px">Sin factores de riesgo detectados</div>'

        osint_html_section = ""
        if self.osint_result and self.osint_result.has_findings:
            o = self.osint_result
            osint_rows = ""
            if o.org_info:
                org = o.org_info.get("org","") or o.org_info.get("shodan_org","")
                asn = o.org_info.get("asn","")
                isp = o.org_info.get("shodan_isp","")
                city = o.org_info.get("shodan_city","")
                country = o.org_info.get("shodan_country","")
                if org: osint_rows += f"<tr><td>Organización</td><td>{org}</td></tr>"
                if asn: osint_rows += f"<tr><td>ASN</td><td>{asn}</td></tr>"
                if isp: osint_rows += f"<tr><td>ISP</td><td>{isp}</td></tr>"
                if city: osint_rows += f"<tr><td>Ciudad</td><td>{city}, {country}</td></tr>"
            if o.subdomains:
                subs = ", ".join(sorted(o.subdomains)[:20])
                more = f" (+{len(o.subdomains)-20} más)" if len(o.subdomains) > 20 else ""
                osint_rows += f"<tr><td>Subdominios ({len(o.subdomains)})</td><td style='font-family:monospace;font-size:11px'>{subs}{more}</td></tr>"
            if o.emails:
                osint_rows += f"<tr><td>Emails expuestos</td><td style='font-family:monospace;font-size:11px'>{', '.join(sorted(o.emails))}</td></tr>"
            if o.technologies:
                osint_rows += f"<tr><td>Tecnologías (OSINT)</td><td>{', '.join(sorted(o.technologies))}</td></tr>"
            if o.sources_used:
                osint_rows += f"<tr><td>Fuentes consultadas</td><td>{', '.join(o.sources_used)}</td></tr>"
            if osint_rows:
                osint_html_section = f"""
<section>
  <h2>Inteligencia OSINT</h2>
  <table>
    <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
    <tbody>{osint_rows}</tbody>
  </table>
</section>"""
        creds_html_section = ""
        if self.credentials:
            def _cred_badge(tool):
                m = {"hydra":"critical","nmap":"high"}
                return m.get(tool,"medium")
            creds_rows = ""
            for c in self.credentials:
                creds_rows += f"""
                <tr>
                  <td><strong>{c.get('service','?')}</strong></td>
                  <td>{c.get('port','?')}</td>
                  <td style="color:#f85149;font-family:monospace">{c.get('user','?')}</td>
                  <td style="color:#f85149;font-family:monospace">{c.get('password','?')}</td>
                  <td><span class="badge {_cred_badge(c.get('tool',''))}">{c.get('tool','?')}</span></td>
                </tr>"""
            creds_html_section = f"""
<section style="border-color:#f8514966;background:#f8514908">
  <h2 style="color:#f85149">⚠ Credenciales Obtenidas ({len(self.credentials)})</h2>
  <table>
    <thead><tr><th>Servicio</th><th>Puerto</th><th>Usuario</th><th>Password</th><th>Tool</th></tr></thead>
    <tbody>{creds_rows}</tbody>
  </table>
</section>"""
        tool_colors = {
            "nmap":"#58a6ff","rustscan":"#58a6ff","masscan":"#58a6ff",
            "nikto":"#d29922","gobuster":"#d29922","whatweb":"#d29922",
            "wpscan":"#d29922","nuclei":"#f85149","sqlmap":"#f85149",
            "hydra":"#f85149","metasploit":"#f85149","msfconsole":"#f85149",
            "sslscan":"#bc8cff","enum4linux":"#e3b341","smbclient":"#e3b341",
        }
        tools_pills_html = ""
        for t in self.tools_ran:
            base = t.split(":")[0].lower()
            color = tool_colors.get(base, "#3fb950")
            tools_pills_html += f'<span class="tech-pill" style="background:{color}22;border:1px solid {color}44;color:{color}">{t}</span>'

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>THOR — {display_target}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --cyan: #58a6ff; --green: #3fb950; --red: #f85149;
    --orange: #d29922; --yellow: #e3b341; --purple: #bc8cff;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; font-size:14px; line-height:1.6 }}
  a {{ color:var(--cyan); text-decoration:none }} a:hover {{ text-decoration:underline }}

  header {{ background:var(--bg2); border-bottom:1px solid var(--border); padding:20px 40px; display:flex; align-items:center; gap:20px }}
  .logo {{ font-family:monospace; font-size:22px; color:var(--cyan); font-weight:700; letter-spacing:4px }}
  .header-info {{ flex:1 }}
  .target-name {{ font-size:20px; font-weight:600 }}
  .scan-meta {{ color:var(--text2); font-size:12px }}

  .risk-badge {{ padding:6px 18px; border-radius:20px; font-weight:700; font-size:13px; background:{risk_color}22; color:{risk_color}; border:1px solid {risk_color}44 }}

  main {{ max-width:1200px; margin:0 auto; padding:30px 20px }}

  .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:30px }}
  .stat-card {{ background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:16px; text-align:center }}
  .stat-num {{ font-size:32px; font-weight:700; line-height:1 }}
  .stat-label {{ color:var(--text2); font-size:11px; margin-top:4px; text-transform:uppercase; letter-spacing:1px }}
  .stat-red {{ color:var(--red) }} .stat-orange {{ color:var(--orange) }} .stat-green {{ color:var(--green) }} .stat-cyan {{ color:var(--cyan) }}

  section {{ background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:20px; margin-bottom:20px }}
  h2 {{ font-size:16px; font-weight:600; color:var(--cyan); margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border) }}
  h3 {{ font-size:13px; font-weight:600; margin:16px 0 8px }}

  table {{ width:100%; border-collapse:collapse }}
  th {{ text-align:left; color:var(--text2); font-size:11px; text-transform:uppercase; letter-spacing:1px; padding:8px; border-bottom:1px solid var(--border) }}
  td {{ padding:8px; border-bottom:1px solid var(--border)22; font-family:monospace; font-size:13px }}
  tr:hover td {{ background:var(--bg3) }}
  .version {{ color:var(--text2); font-size:12px }}

  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; margin-left:6px }}
  .critical {{ background:#f8514922; color:#f85149; border:1px solid #f8514944 }}
  .high     {{ background:#d2992222; color:#d29922; border:1px solid #d2992244 }}
  .medium   {{ background:#e3b34122; color:#e3b341; border:1px solid #e3b34144 }}
  .low      {{ background:#3fb95022; color:#3fb950; border:1px solid #3fb95044 }}
  .info     {{ background:#58a6ff22; color:#58a6ff; border:1px solid #58a6ff44 }}

  .cve-card {{ background:var(--bg3); border:1px solid var(--border); border-radius:6px; padding:12px 16px; margin-bottom:10px }}
  .cve-exploit {{ border-color:#f8514966; background:#f8514908 }}
  .cve-header {{ display:flex; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:8px }}
  .cve-id {{ font-family:monospace; font-weight:700; color:var(--text); font-size:14px }}
  .cve-db {{ color:var(--text2); font-size:11px; margin-left:auto }}
  .cve-links {{ display:flex; gap:12px; flex-wrap:wrap }}
  .cve-links a {{ font-size:12px; background:var(--bg2); border:1px solid var(--border); padding:3px 10px; border-radius:4px }}
  .exploit-badge {{ background:#f8514922; color:#f85149; border:1px solid #f8514944; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700 }}
  .exploit-link {{ background:#f8514922 !important; color:#f85149 !important; border-color:#f8514966 !important }}

  .tech-pill {{ display:inline-block; background:var(--bg3); border:1px solid var(--border); border-radius:12px; padding:3px 10px; margin:3px; font-size:12px; color:var(--text2) }}

  ul {{ padding-left:20px }}
  li {{ margin-bottom:6px; font-size:13px }}
  code {{ background:var(--bg3); border:1px solid var(--border); border-radius:3px; padding:1px 5px; font-family:monospace; font-size:12px; color:var(--purple) }}

  .bar-wrap {{ background:var(--bg3); border-radius:4px; height:8px; margin-top:8px }}
  .bar {{ height:8px; border-radius:4px; background:{risk_color}; transition:width 1s }}

  footer {{ text-align:center; color:var(--text2); font-size:11px; padding:20px; border-top:1px solid var(--border); margin-top:20px }}
</style>
</head>
<body>
<header>
  <div class="logo">⚡ THOR</div>
  <div class="header-info">
    <div class="target-name">{display_target}</div>
    <div class="scan-meta">{ts} · Duración: {elapsed} · OS: {self.os_guess or 'No detectado'}</div>
  </div>
  <div class="risk-badge">{self.risk_level} — {self.risk_score} pts</div>
</header>
<main>
<div class="stats-grid">
  <div class="stat-card"><div class="stat-num stat-cyan">{len(self.open_ports)}</div><div class="stat-label">Puertos abiertos</div></div>
  <div class="stat-card"><div class="stat-num stat-red">{len(self.cves)}</div><div class="stat-label">CVEs totales</div></div>
  <div class="stat-card"><div class="stat-num stat-red">{len(exploit_cves)}</div><div class="stat-label">Exploits públicos</div></div>
  <div class="stat-card"><div class="stat-num stat-orange">{len(self.findings)}</div><div class="stat-label">Findings</div></div>
  <div class="stat-card"><div class="stat-num stat-green">{len(self.tools_ran)}</div><div class="stat-label">Tools ejecutadas</div></div>
  <div class="stat-card"><div class="stat-num" style="color:{risk_color}">{self.risk_score}</div><div class="stat-label">Risk Score</div><div class="bar-wrap"><div class="bar" style="width:{min(100,self.risk_score//2)}%;background:{risk_color}"></div></div></div>
</div>

<section style="border-color:{risk_color}44;background:{risk_color}08">
  <h2 style="color:{risk_color}">Risk Rate — {self.risk_level} ({self.risk_score} pts)</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:20px">
    <div style="grid-column:1/-1">
      <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text2);margin-bottom:6px">
        <span>INFORMATIVO</span><span>BAJO</span><span>MEDIO</span><span>ALTO</span><span>CRÍTICO</span>
      </div>
      <div style="height:12px;border-radius:6px;background:linear-gradient(to right,#3fb950,#e3b341,#d29922,#f85149);position:relative">
        <div style="position:absolute;top:-4px;left:{min(98,self.risk_score//2)}%;transform:translateX(-50%);width:8px;height:20px;background:white;border-radius:2px;border:2px solid {risk_color}"></div>
      </div>
      <div style="text-align:center;margin-top:8px;font-size:13px;font-weight:700;color:{risk_color}">
        Score: {self.risk_score} / 200+ pts → {self.risk_level}
      </div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:16px">
      <div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:12px;text-transform:uppercase;letter-spacing:1px">Desglose del Score</div>
      {score_breakdown_html}
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:16px">
      <div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:12px;text-transform:uppercase;letter-spacing:1px">Tabla de Clasificación</div>
      <table style="width:100%;font-size:12px">
        <tr><td style="padding:4px 8px"><span class="badge info">INFORMATIVO</span></td><td style="color:var(--text2)">0–9 pts</td></tr>
        <tr><td style="padding:4px 8px"><span class="badge low">BAJO</span></td><td style="color:var(--text2)">10–39 pts</td></tr>
        <tr><td style="padding:4px 8px"><span class="badge medium">MEDIO</span></td><td style="color:var(--text2)">40–79 pts</td></tr>
        <tr><td style="padding:4px 8px"><span class="badge high">ALTO</span></td><td style="color:var(--text2)">80–149 pts</td></tr>
        <tr><td style="padding:4px 8px"><span class="badge critical">CRÍTICO</span></td><td style="color:var(--text2)">150+ pts</td></tr>
      </table>
    </div>
  </div>
</section>
{osint_html_section}
<section><h2>Puertos Abiertos ({len(self.open_ports)})</h2><table><thead><tr><th>Puerto</th><th>Proto</th><th>Servicio</th><th>Versión</th></tr></thead><tbody>{ports_rows}</tbody></table></section>
{'<section><h2>Stack Tecnológico</h2>' + tech_pills + '</section>' if self.tech_stack else ''}
{'<section><h2>CVEs Encontrados (' + str(len(self.cves)) + ')</h2>' + cves_html + '</section>' if self.cves else ''}
{'<section><h2>Hallazgos de Seguridad</h2>' + findings_html + '</section>' if self.findings else ''}
{creds_html_section}
<section><h2>Herramientas Ejecutadas ({len(self.tools_ran)})</h2><div style="display:flex;flex-wrap:wrap;gap:8px">{tools_pills_html}</div></section>
</main>
<footer>THOR Framework v6.0 · Auto Module · {ts}</footer>
</body>
</html>"""
        self.report_html.write_text(html, encoding='utf-8')
        return self.report_html

    def show_rich_summary(self):
        if not HAS_RICH:
            return
        console.print()
        t = Table(title=f"Puertos abiertos — {self.target}", box=box.ROUNDED, style="cyan")
        t.add_column("Puerto", style="green")
        t.add_column("Proto")
        t.add_column("Servicio", style="bold")
        t.add_column("Versión", style="dim")
        for p in self.open_ports:
            t.add_row(str(p["port"]), p["proto"], p["service"], p["version"])
        console.print(t)
        console.print()
        if self.findings:
            f_table = Table(title="Hallazgos", box=box.ROUNDED)
            f_table.add_column("Severidad")
            f_table.add_column("Tool")
            f_table.add_column("Puerto")
            f_table.add_column("Detalle")
            sev_colors = {"CRÍTICO":"red","ALTO":"yellow","MEDIO":"cyan","BAJO":"green"}
            for f in sorted(self.findings, key=lambda x: ["CRÍTICO","ALTO","MEDIO","BAJO"].index(x["severity"]) if x["severity"] in ["CRÍTICO","ALTO","MEDIO","BAJO"] else 99):
                color = sev_colors.get(f["severity"], "white")
                f_table.add_row(f"[{color}]{f['severity']}[/{color}]", f["tool"], str(f["port"]), f["detail"][:80])
            console.print(f_table)
            console.print()
        if self.cves:
            c_table = Table(title=f"CVEs ({len(self.cves)})", box=box.ROUNDED)
            c_table.add_column("CVE", style="red")
            c_table.add_column("CVSS")
            c_table.add_column("NVD")
            for c in self.cves:
                c_table.add_row(c["cve"], c.get("cvss","N/A"), f"https://nvd.nist.gov/vuln/detail/{c['cve']}")
            console.print(c_table)
            console.print()
        risk_colors = {"CRÍTICO":"red","ALTO":"yellow","MEDIO":"cyan","BAJO":"green","INFORMATIVO":"dim"}
        color = risk_colors.get(self.risk_level, "white")
        console.print(Panel(
            f"[{color}]{self.risk_level}[/{color}] — Score: [bold]{self.risk_score}[/bold] pts\n"
            f"CVEs: [red]{len(self.cves)}[/red]  Findings: [yellow]{len(self.findings)}[/yellow]  Tools: {len(self.tools_ran)}",
            title="Risk Rate",
            border_style=color
        ))
        console.print()

    def _report_no_ports(self):
        print()
        print(f"  {C.B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
        print(f"  {C.Y}  ANÁLISIS DE RESULTADO: SIN PUERTOS DETECTADOS{C.N}")
        print(f"  {C.B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
        print()
        if self.is_local:
            print(f"  {C.R}▶{C.N}  {C.W}Host LAN sin puertos visibles{C.N}")
            print(f"     Probablemente el host está apagado o inaccesible.")
        else:
            print(f"  {C.G}▶{C.N}  {C.W}Sistema bien asegurado o con protección activa{C.N}")
            print(f"     Ninguna de las 6 técnicas de evasión logró detectar puertos abiertos.")
            print()
            print(f"  {C.C}Técnicas intentadas:{C.N}")
            tecnicas = [
                ("SYN Scan",           "Escaneo estándar de semiapertura TCP"),
                ("TCP Connect",        "Conexión completa — bypass algunos firewalls"),
                ("Puertos comunes",    "Lista forzada de 30 puertos críticos"),
                ("Fragmentación MTU",  "Paquetes divididos para evadir IDS/IPS"),
                ("UDP Services",       "Servicios UDP: DNS, SNMP, NTP, TFTP"),
                ("ACK Scan",           "Mapeo de reglas del firewall"),
            ]
            for t, d in tecnicas:
                print(f"     {C.D}✗{C.N}  {C.Y}{t:<22}{C.N} {C.D}{d}{C.N}")
        print()
        print(f"  {C.B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
        print(f"  {C.W}Conclusión:{C.N} El objetivo tiene una postura de seguridad")
        print(f"  perimetral {C.G}sólida{C.N}. Se recomienda recon pasivo adicional")
        print(f"  (OSINT, certificados SSL, registros DNS, Shodan) antes")
        print(f"  de intentar técnicas más agresivas.")
        print(f"  {C.B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
        print()

    def run(self):
        if sys.stdout.isatty():
            print_banner()
        else:
            print(f"{C.Y}[THOR] Iniciando análisis para {self.target}{C.N}")
        print(f"  {C.C}TARGET:{C.N} {C.W}{self.target}{C.N}  │  "
              f"{C.C}RED:{C.N} {'LAN' if self.is_local else 'Internet'}  │  "
              f"{C.C}OUT:{C.N} {self.outdir}\n")

        if sys.stdout.isatty():
            available = [t for t, v in self.tools.items() if v]
            missing   = [t for t, v in self.tools.items() if not v]
            COL = 20; COLS = 3
            print(f"  {C.C}━━━ TOOLS DISPONIBLES ━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
            for i in range(0, len(available), COLS):
                row = available[i:i+COLS]
                line = "  "
                for t in row:
                    line += f"{C.G}✓{C.N} {C.G}{t:<{COL}}{C.N}"
                print(line)
            if missing:
                print(f"  {C.D}━━━ Faltantes ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
                for i in range(0, len(missing), COLS):
                    row = missing[i:i+COLS]
                    line = "  "
                    for t in row:
                        line += f"{C.Y}✗{C.N} {C.D}{t:<{COL}}{C.N}"
                    print(line)
            print()

        self.phase0_passive()
        print()
        if not self.phase1_ports():
            self._report_no_ports()
            return
        print()
        self.phase2_services()
        print()
        plan = self.phase3_decide()
        print()
        self.phase4_nse(plan)
        print()
        self.phase5_targeted(plan)
        print()
        self.phase6_score()
        self.show_rich_summary()
        self.phase7_report()
        print()
        print(f"  {C.B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}")
        print(f"  {C.G}[✓] Análisis completado{C.N}")
        print(f"  {C.W}Ver reporte:{C.N} less {self.report_txt}")
        print(f"  {C.W}Markdown:  {C.N} {self.report_md}")
        print(f"  {C.W}JSON:      {C.N} {self.report_json}")
        print()
