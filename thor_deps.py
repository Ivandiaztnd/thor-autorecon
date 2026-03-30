#!/usr/bin/env python3
# ============================================================
#  THOR DEPENDENCIES MODULE
#  Gestión de instalación y verificación de herramientas
# ============================================================

import subprocess, os, sys, re, platform, shutil
from pathlib import Path

# ── colores ────────────────────────────────────────────────
class C:
    R='\033[1;31m'; G='\033[1;32m'; Y='\033[1;33m'
    B='\033[0;34m'; M='\033[1;35m'; C='\033[0;36m'
    W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'

# ════════════════════════════════════════════════════════════
#  MAPA DE DEPENDENCIAS
# ════════════════════════════════════════════════════════════
DEPS = {
    "nmap":        ("nmap",                    "Port scanner principal",          True),
    "curl":        ("curl",                    "HTTP client",                     True),
    "git":         ("git",                     "Clonar vulscan y otros repos",    True),
    "python3":     ("python3",                 "Runtime Python",                  True),
    "nikto":       ("nikto",                   "Web vuln scanner",                False),
    "gobuster":    ("gobuster",                "Directory bruteforce",            False),
    "whatweb":     ("whatweb",                 "Web tech fingerprint",            False),
    "hydra":       ("hydra",                   "Brute force (solo recon)",        False),
    "sqlmap":      ("sqlmap",                  "SQL injection detection",         False),
    "smbclient":   ("smbclient",               "SMB share enumeration",           False),
    "enum4linux":  (None,                      "SMB/AD enumeration (Portcullis)", False),
    "sslscan":     ("sslscan",                 "SSL/TLS audit",                   False),
    "masscan":     ("masscan",                 "Fast port scanner",               False),
    "whois":       ("whois",                   "Domain info lookup",              False),
    "dig":         ("dnsutils",                "DNS resolution",                  False),
    "nbtscan":     ("nbtscan",                 "NetBIOS scanner",                 False),
    "jq":          ("jq",                      "JSON parser",                     False),
    "rustscan":    (None,                      "Ultra-fast port scanner",         False),
    "nuclei":      (None,                      "Template-based vuln scanner",     False),
    "wpscan":      (None,                      "WordPress scanner",               False),
}

def dep_status(msg, level="info"):
    icons = {"ok": f"{C.G}[OK]{C.N}", "fail": f"{C.R}[NO]{C.N}",
             "info": f"{C.Y}[*]{C.N}", "inst": f"{C.C}[+]{C.N}",
             "warn": f"{C.Y}[!]{C.N}"}
    print(f"  {icons.get(level,'[?]')} {msg}")

def run_apt(packages):
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    r = subprocess.run(
        ["apt-get", "install", "-y", "-q",
         "-o", "Dpkg::Options::=--force-confdef",
         "-o", "Dpkg::Options::=--force-confold"] + packages,
        capture_output=True, text=True, env=env, timeout=300)
    return r.returncode == 0

def install_rustscan():
    dep_status("Descargando RustScan desde SourceForge...", "inst")
    arch = platform.machine()
    arch_map = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armhf"}
    deb_arch = arch_map.get(arch, "amd64")
    deb_path = f"/tmp/rustscan_{deb_arch}.deb"
    sources = [
        f"https://sourceforge.net/projects/rustscan.mirror/files/latest/download",
        f"https://github.com/RustScan/RustScan/releases/latest/download/rustscan_{deb_arch}.deb",
    ]
    downloaded = False
    for url in sources:
        r = subprocess.run(["curl", "-fsSL", "--max-time", "120", "-o", deb_path, url],
                           capture_output=True, timeout=180)
        if r.returncode == 0 and Path(deb_path).exists() and Path(deb_path).stat().st_size > 100_000:
            downloaded = True
            break
    if not downloaded:
        dep_status("No se pudo descargar RustScan", "fail")
        return False
    subprocess.run(["dpkg", "-i", deb_path], capture_output=True, timeout=60)
    Path(deb_path).unlink(missing_ok=True)
    if shutil.which("rustscan"):
        dep_status("RustScan instalado", "ok")
        return True
    return False

def install_nuclei():
    dep_status("Descargando Nuclei...", "inst")
    out = subprocess.run(["curl", "-s", "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"],
                         capture_output=True, text=True, timeout=30).stdout
    url = ""
    for line in out.splitlines():
        if "linux_amd64.zip" in line and "browser_download_url" in line:
            m = re.search(r'"(https://[^"]+\.zip)"', line)
            if m:
                url = m.group(1)
                break
    if not url:
        dep_status("No se pudo obtener URL de Nuclei", "fail")
        return False
    zip_path = "/tmp/nuclei_latest.zip"
    subprocess.run(["curl", "-sL", url, "-o", zip_path], capture_output=True, timeout=180)
    subprocess.run(["unzip", "-o", zip_path, "nuclei", "-d", "/usr/local/bin/"], capture_output=True)
    subprocess.run(["chmod", "+x", "/usr/local/bin/nuclei"], capture_output=True)
    Path(zip_path).unlink(missing_ok=True)
    if shutil.which("nuclei"):
        dep_status("Nuclei instalado", "ok")
        tpl_path = "/root/nuclei-templates"
        if not Path(tpl_path).exists():
            subprocess.run(["git", "clone", "--depth", "1",
                            "https://github.com/projectdiscovery/nuclei-templates.git", tpl_path],
                           capture_output=True, timeout=300)
        return True
    return False

def install_wpscan():
    dep_status("Instalando dependencias Ruby para WPScan...", "inst")
    ruby_deps = ["ruby", "ruby-dev", "build-essential", "libcurl4-openssl-dev", "libxml2", "libxml2-dev",
                 "libxslt1-dev", "zlib1g-dev"]
    subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
    run_apt(ruby_deps)
    if not shutil.which("gem"):
        dep_status("gem no encontrado", "fail")
        return False
    dep_status("gem install wpscan (puede tardar ~2 min)...", "inst")
    r = subprocess.run(["gem", "install", "wpscan"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        dep_status(f"gem install falló: {r.stderr.strip()[:120]}", "fail")
        return False
    if not shutil.which("wpscan"):
        for candidate in ["/usr/local/bin/wpscan", "/var/lib/gems/3.1.0/bin/wpscan",
                          "/var/lib/gems/3.0.0/bin/wpscan", Path.home() / ".gem/ruby/3.1.0/bin/wpscan",
                          Path.home() / ".gem/ruby/3.0.0/bin/wpscan"]:
            if Path(candidate).exists():
                symlink = Path("/usr/local/bin/wpscan")
                if not symlink.exists():
                    symlink.symlink_to(candidate)
                dep_status(f"wpscan encontrado en {candidate} → symlink creado", "ok")
                break
    if not shutil.which("wpscan"):
        dep_status("wpscan no disponible en PATH", "fail")
        return False
    subprocess.run(["wpscan", "--update"], capture_output=True, timeout=180)
    return True

def install_enum4linux():
    dep_status("Descargando enum4linux desde Portcullis Labs...", "inst")
    base_url = "https://labs.portcullis.co.uk/download"
    tmp_dir = Path("/tmp/enum4linux_install")
    tmp_dir.mkdir(exist_ok=True)
    listing_url = base_url + "/"
    r = subprocess.run(["curl", "-fsSL", "--max-time", "30", listing_url],
                       capture_output=True, text=True, timeout=45)
    tarball_url = ""
    latest_ver = (0,0,0)
    if r.returncode == 0:
        for m in re.finditer(r'enum4linux-(\d+)\.(\d+)\.(\d+)\.tar\.gz', r.stdout):
            ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if ver > latest_ver:
                latest_ver = ver
                tarball_url = f"{base_url}/{m.group(0)}"
    if not tarball_url:
        tarball_url = f"{base_url}/enum4linux-0.8.3.tar.gz"
    tar_path = tmp_dir / "enum4linux.tar.gz"
    r = subprocess.run(["curl", "-fsSL", "--max-time", "120", tarball_url, "-o", str(tar_path)],
                       capture_output=True, timeout=180)
    if r.returncode != 0 or not tar_path.exists() or tar_path.stat().st_size < 5_000:
        gh_url = "https://github.com/CiscoCXSecurity/enum4linux/archive/refs/heads/master.tar.gz"
        r2 = subprocess.run(["curl", "-fsSL", "--max-time", "120", gh_url, "-o", str(tar_path)],
                            capture_output=True, timeout=180)
        if r2.returncode != 0:
            dep_status("No se pudo descargar enum4linux", "fail")
            return False
    extract_dir = tmp_dir / "extracted"
    extract_dir.mkdir(exist_ok=True)
    subprocess.run(["tar", "-xzf", str(tar_path), "-C", str(extract_dir)], capture_output=True, timeout=30)
    enum_script = None
    for candidate in extract_dir.rglob("enum4linux.pl"):
        enum_script = candidate
        break
    if not enum_script:
        for candidate in extract_dir.rglob("enum4linux*.pl"):
            enum_script = candidate
            break
    if not enum_script:
        dep_status("No se encontró enum4linux.pl", "fail")
        return False
    dest = Path("/usr/local/bin/enum4linux")
    shutil.copy2(str(enum_script), str(dest))
    dest.chmod(0o755)
    lib_dir = Path("/usr/local/lib/enum4linux")
    lib_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(enum_script), str(lib_dir / "enum4linux.pl"))
    wrapper = Path("/usr/local/bin/enum4linux")
    wrapper.write_text("#!/bin/bash\nexec perl /usr/local/lib/enum4linux/enum4linux.pl \"$@\"\n")
    wrapper.chmod(0o755)
    subprocess.run(["apt-get", "install", "-y", "-q", "libio-socket-ssl-perl"], capture_output=True)
    shutil.rmtree(str(tmp_dir), ignore_errors=True)
    if shutil.which("enum4linux"):
        return True
    return False

#def install_metasploit():
#    dep_status("Descargando instalador Rapid7...", "inst")
#    installer = "/tmp/msfinstall"
#    r = subprocess.run(["curl", "-sSL", "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb", "-o", installer],
#                       capture_output=True, timeout=60)
#    if r.returncode != 0:
#        dep_status("No se pudo descargar el instalador de MSF", "fail")
#        return False
#    os.chmod(installer, 0o755)
#    subprocess.run(["bash", installer], capture_output=True, timeout=600)
#    Path(installer).unlink(missing_ok=True)
#    if shutil.which("msfconsole"):
#        return True
#    return False

def install_vulscan_nse():
    install_path = "/usr/share/nmap/scripts/vulscan"
    if Path(install_path).exists():
        return True
    r = subprocess.run(["git", "clone", "--depth", "1", "https://github.com/scipag/vulscan", install_path],
                       capture_output=True, timeout=180)
    if r.returncode == 0:
        subprocess.run(["nmap", "--script-updatedb"], capture_output=True, timeout=60)
        return True
    return False

def install_rich():
    r = subprocess.run([sys.executable, "-m", "pip", "install", "rich", "--break-system-packages", "-q"],
                       capture_output=True, timeout=120)
    return r.returncode == 0

def has_tool(name):
    if shutil.which(name):
        return True
    extra_paths = {
        "rustscan": ["/usr/bin/rustscan", "/usr/local/bin/rustscan"],
        "nuclei": ["/usr/local/bin/nuclei", "/root/go/bin/nuclei", str(Path.home() / "go/bin/nuclei")],
        "wpscan": ["/usr/local/bin/wpscan", "/var/lib/gems/3.3.0/bin/wpscan", "/var/lib/gems/3.2.0/bin/wpscan"],
        "enum4linux": ["/usr/local/bin/enum4linux", "/usr/bin/enum4linux", "/usr/local/lib/enum4linux/enum4linux.pl"],
        "gobuster": ["/usr/local/bin/gobuster", "/root/go/bin/gobuster", str(Path.home() / "go/bin/gobuster")],
    }
    for p in extra_paths.get(name, []):
        if Path(p).exists():
            symlink = Path(f"/usr/local/bin/{name}")
            if not symlink.exists():
                try:
                    symlink.symlink_to(p)
                except Exception:
                    pass
            return True
    dpkg_names = {
         "rustscan": "rustscan", "enum4linux": "enum4linux",
        "nuclei": "nuclei", "gobuster": "gobuster", "nikto": "nikto", "whatweb": "whatweb",
        "hydra": "hydra", "sqlmap": "sqlmap", "smbclient": "smbclient", "sslscan": "sslscan",
        "masscan": "masscan", "nbtscan": "nbtscan",
    }
    pkg = dpkg_names.get(name)
    if pkg:
        r = subprocess.run(["dpkg", "-l", pkg], capture_output=True, text=True)
        if any(line.startswith("ii") for line in r.stdout.splitlines()):
            return True
    search_dirs = ["/usr/bin", "/usr/local/bin", "/usr/sbin", "/opt", "/var/lib/gems",
                   str(Path.home() / "go/bin"), str(Path.home() / ".gem"), str(Path.home() / ".local/bin")]
    for d in search_dirs:
        if not Path(d).exists():
            continue
        r = subprocess.run(["find", d, "-name", name, "-type", "f", "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*"],
                           capture_output=True, text=True, timeout=5)
        if r.stdout.strip():
            found_path = r.stdout.strip().splitlines()[0]
            symlink = Path(f"/usr/local/bin/{name}")
            if not symlink.exists():
                try:
                    symlink.symlink_to(found_path)
                except Exception:
                    pass
            return True
    if name == "wpscan" and shutil.which("gem"):
        r = subprocess.run(["gem", "list"], capture_output=True, text=True)
        if "wpscan" in r.stdout.lower():
            gem_bin = subprocess.run(["gem", "environment", "gemdir"], capture_output=True, text=True).stdout.strip()
            if gem_bin:
                wp = Path(gem_bin) / "bin" / "wpscan"
                if wp.exists():
                    symlink = Path("/usr/local/bin/wpscan")
                    if not symlink.exists():
                        try:
                            symlink.symlink_to(str(wp))
                        except Exception:
                            pass
                    return True
    return False

def check_and_install_deps(silent=False):
    if not silent:
        print(f"\n  {C.C}━━━ VERIFICACIÓN DE DEPENDENCIAS ━━━━━━━━━━━━━━━━━━━━━━━━━━{C.N}\n")
    states = {}
    missing_apt = []
    missing_special = []
    missing_critical = []
    for tool, (pkg, desc, critical) in DEPS.items():
        found = has_tool(tool)
        states[tool] = found
        if not found:
            if critical:
                missing_critical.append((tool, pkg, desc))
            elif pkg is not None:
                missing_apt.append((tool, pkg, desc))
            else:
                missing_special.append((tool, desc))
    if not silent:
        ok_tools = [t for t, v in states.items() if v]
        fail_tools = [t for t, v in states.items() if not v]
        print(f"  {C.G}Disponibles ({len(ok_tools)}):{C.N}  {' '.join(ok_tools)}")
        if fail_tools:
            print(f"  {C.Y}Faltantes   ({len(fail_tools)}):{C.N}  {' '.join(fail_tools)}")
        print()
    all_missing = missing_critical + missing_apt + missing_special
    if not all_missing:
        if not silent:
            dep_status("Todas las dependencias satisfechas", "ok")
        return states
    # Modo silencioso
    if silent:
        if missing_critical:
            apt_pkgs = [pkg for tool, pkg, desc in missing_critical if pkg]
            if apt_pkgs:
                dep_status("Instalando dependencias críticas automáticamente...", "inst")
                subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
                run_apt(apt_pkgs)
            for tool, pkg, desc in missing_critical:
                states[tool] = has_tool(tool)
        if missing_apt:
            apt_pkgs = [pkg for tool, pkg, desc in missing_apt if pkg]
            if apt_pkgs:
                subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
                run_apt(apt_pkgs)
            for tool, pkg, desc in missing_apt:
                states[tool] = has_tool(tool)
        return states
    # --- Modo interactivo ---
    if missing_critical:
        print(f"  {C.R}[!] Herramientas CRÍTICAS faltantes:{C.N}")
        for tool, pkg, desc in missing_critical:
            print(f"      {C.R}✗{C.N}  {tool:15} {C.D}({desc}){C.N}")
        print()
    if missing_apt:
        print(f"  {C.Y}[*] Herramientas APT faltantes:{C.N}")
        for tool, pkg, desc in missing_apt:
            print(f"      {C.Y}○{C.N}  {tool:15} {C.D}({desc}){C.N}")
        print()
    if missing_special:
        print(f"  {C.C}[*] Herramientas especiales faltantes:{C.N}")
        for tool, desc in missing_special:
            print(f"      {C.C}○{C.N}  {tool:15} {C.D}({desc}){C.N}")
        print()
    install_apt_flag = False
    install_spec_flag = {}
    if missing_critical or missing_apt:
        try:
            ans = input(f"  {C.W}¿Instalar paquetes APT faltantes? [S/n]: {C.N}").strip().lower()
            install_apt_flag = ans not in ("n", "no")
        except (KeyboardInterrupt, EOFError):
            print()
            if missing_critical:
                print(f"\n  {C.R}[!] Herramientas críticas requeridas — abortando{C.N}")
                sys.exit(1)
            install_apt_flag = False
#    for tool, desc in missing_special:
#        if tool == "msfconsole":
#            prompt = f"  {C.Y}¿Instalar Metasploit Framework? (~500MB, tarda varios min) [s/N]: {C.N}"
#            default = False
#        else:
#            prompt = f"  {C.W}¿Instalar {tool}? ({desc}) [S/n]: {C.N}"
#            default = True
#        try:
#            ans = input(prompt).strip().lower()
#            if tool == "msfconsole":
#                install_spec_flag[tool] = ans in ("s", "si", "sí", "y", "yes")
#            else:
#                install_spec_flag[tool] = ans not in ("n", "no")
#        except (KeyboardInterrupt, EOFError):
#            print()
#            install_spec_flag[tool] = False
#            dep_status(f"{tool} omitido", "warn")
#    print()
    if install_apt_flag:
        apt_pkgs = []
        for tool, pkg, desc in missing_critical + missing_apt:
            if pkg and not has_tool(tool):
                apt_pkgs.append(pkg)
        if apt_pkgs:
            apt_pkgs = list(set(apt_pkgs))
            dep_status(f"apt-get install {' '.join(apt_pkgs)}", "inst")
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=120)
            if run_apt(apt_pkgs):
                dep_status("Paquetes APT instalados", "ok")
            else:
                dep_status("Algunos paquetes apt fallaron — continuando", "warn")
    else:
        if missing_critical:
            print(f"\n  {C.R}[!] Sin herramientas críticas — abortando{C.N}")
            sys.exit(1)
        dep_status("Paquetes APT omitidos", "warn")
    for tool, desc in missing_special:
        if has_tool(tool):
            continue
        if not install_spec_flag.get(tool, False):
            dep_status(f"{tool} omitido — algunas funciones no estarán disponibles", "warn")
            continue
        print()
        dep_status(f"Instalando {tool}...", "inst")
        if tool == "rustscan":
            states["rustscan"] = install_rustscan()
        elif tool == "enum4linux":
            states["enum4linux"] = install_enum4linux()
        elif tool == "nuclei":
            states["nuclei"] = install_nuclei()
        elif tool == "wpscan":
            states["wpscan"] = install_wpscan()
        elif tool == "msfconsole":
            states["msfconsole"] = install_metasploit()
    vulscan_path = "/usr/share/nmap/scripts/vulscan/vulscan.nse"
    if not Path(vulscan_path).exists() and shutil.which("nmap") and shutil.which("git"):
        print()
        dep_status("Instalando vulscan NSE (multi-DB offline)...", "inst")
        install_vulscan_nse()
    global HAS_RICH, console
    if not HAS_RICH:
        dep_status("Instalando rich (dashboard)...", "inst")
        if install_rich():
            try:
                from rich.console import Console
                from rich.table import Table
                from rich.panel import Panel
                from rich import box
                HAS_RICH = True
                console = Console()
                dep_status("rich instalado", "ok")
            except ImportError:
                pass
    print()
    dep_status("Verificación post-instalación:", "info")
    for tool in DEPS:
        states[tool] = has_tool(tool)
        icon = f"{C.G}✓{C.N}" if states[tool] else f"{C.Y}✗{C.N}"
        print(f"    {icon}  {tool}")
    still_missing_critical = [t for t, (p, d, crit) in DEPS.items() if crit and not states[t]]
    if still_missing_critical:
        print(f"\n  {C.R}[!] Críticas aún faltantes: {', '.join(still_missing_critical)}{C.N}")
        sys.exit(1)
    print()
    return states

# ================== UTILIDADES BÁSICAS ==================
def cmd(command, timeout=120, shell=False):
    try:
        if shell:
            r = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        else:
            r = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"TIMEOUT after {timeout}s", -1
    except FileNotFoundError:
        return "", f"NOT FOUND: {command[0] if isinstance(command,list) else command}", -1
    except Exception as e:
        return "", str(e), -1

def status(msg, level="info"):
    icons = {"info": f"{C.Y}[*]{C.N}", "ok": f"{C.G}[+]{C.N}",
             "fail": f"{C.R}[!]{C.N}", "brain": f"{C.M}[AI]{C.N}",
             "phase": f"{C.C}[>>]{C.N}"}
    print(f"  {icons.get(level,'[?]')} {msg}")

def is_local(ip):
    try:
        parts = list(map(int, ip.split('.')))
        return (parts[0] == 10 or (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or parts[0] == 127)
    except:
        return False

def sanitize_target(raw):
    t = raw.strip()
    t = re.sub(r'^https?://|^ftp://', '', t, flags=re.I)
    t = t.split('/')[0].split('?')[0].split('#')[0]
    t = re.sub(r'[()[\]{}<>!@#$%^&*;`\s]', '', t)
    return t.strip()

def sanitize_name(s):
    return re.sub(r'[^a-zA-Z0-9._\-]', '_', s)

def print_banner():
    CYAN='\033[0;36m'; Y='\033[1;33m'; B='\033[0;34m'
    NC='\033[0m'; D='\033[0;90m'; R='\033[1;31m'; G='\033[1;32m'
    if sys.stdout.isatty():
        os.system("clear")
    print(f"{Y}    ·  '  ·  .  '  ·  .  '  ·  .  '  ·  .  '  ·{NC}")
    print(f"{Y}  '  -  {CYAN}T H O R   F R A M E W O R K  -  '{NC}")
    print(f"{Y}    ·  '  ·  .  '  ·  .  '  ·  .  '  ·  .  '  ·{NC}")
    print(f"{CYAN}")
    print(f"  ████████╗██╗  ██╗ ██████╗ ██████╗  {D}┌─────────────────────┐{NC}")
    print(f"{CYAN}  ╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗ {D}│  THREAT HUNTING &   │{NC}")
    print(f"{CYAN}     ██║   ███████║██║   ██║██████╔╝  {D}│  OFFENSIVE RECON    │{NC}")
    print(f"{CYAN}     ██║   ██╔══██║██║   ██║██╔══██╗ {D}│  AUTO MODULE v1.0   │{NC}")
    print(f"{CYAN}     ██║   ██║  ██║╚██████╔╝██║  ██║  {D}└─────────────────────┘{NC}")
    print(f"{CYAN}     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝{NC}")
    print()
    print(f"  {B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"  {CYAN}STATUS:{NC} ACTIVE  │  {CYAN}MODE:{NC} {Y}INTELLIGENT RECON{NC}  │  {CYAN}PID:{NC} {os.getpid()}")
    print(f"  {B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print()
