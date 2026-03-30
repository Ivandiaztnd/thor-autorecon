#!/usr/bin/env python3
# ============================================================
#  THOR AUTO v1.0 - Módulo Python Inteligente
#  Recon + Vuln Mapping autónomo, nunca toca el target
#  Uso: python3 thor-auto.py [target] [--output DIR]
# ============================================================

import sys
import argparse
import socket
from pathlib import Path

# Importar módulos personalizados
from thor_deps import check_and_install_deps, status, print_banner
from thor_phases import ThorAuto

def main():
    parser = argparse.ArgumentParser(description="THOR AUTO - Escaneo autónomo")
    parser.add_argument("target", nargs="?", help="IP, dominio o CIDR")
    parser.add_argument("--output", dest="output_dir", help="Directorio de salida (opcional)")
    args = parser.parse_args()

    target = args.target
    if not target:
        target = input("Ingresá el target (IP/dominio/CIDR): ").strip()
        if not target:
            print("Target requerido.")
            sys.exit(1)

    # Verificar dependencias en modo silencioso si se pasó --output (ejecución no interactiva)
    silent_mode = args.output_dir is not None
    dep_states = check_and_install_deps(silent=silent_mode)

    # Resolver hostname
    hostname = None
    try:
        socket.inet_aton(target)
    except socket.error:
        hostname = target
        try:
            target = socket.gethostbyname(hostname)
        except Exception:
            pass

    scanner = ThorAuto(target, hostname=hostname, forced_outdir=args.output_dir)
    scanner.run()

if __name__ == "__main__":
    main()
