import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.units import mm


import docker

DOCKER_IMAGE = "instrumentisto/nmap"

# Scripts NSE à appliquer selon le service détecté
NSE_SCRIPTS = {
    "msrpc":       ["msrpc-enum"],
    "netbios-ssn": ["smb-os-discovery", "smb2-security-mode"],
    "microsoft-ds":["smb-os-discovery", "smb2-security-mode"],
    "mysql":       ["mysql-info", "mysql-empty-password"],
    "http":        ["http-headers", "http-server-header", "http-title"],
    "https":       ["http-headers", "http-server-header", "ssl-cert"],
    "vmware-auth": ["vmware-version"],
    "ssh":         ["ssh2-enum-algos", "banner"],
    "ftp":         ["ftp-anon", "banner"],
    "smtp":        ["smtp-commands", "banner"],
}

@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    product: str
    version: str
    scripts: dict = field(default_factory=dict)  # résultats NSE

def parse_xml(xml_output: str) -> list[Service]:
    root = ET.fromstring(xml_output)
    services = []
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_el = port.find("state")
            svc_el   = port.find("service")
            portid   = port.get("portid")
            if portid is None:
                continue

            # Parse les résultats des scripts NSE
            scripts = {}
            for script in port.findall("script"):
                script_id  = script.get("id", "")
                script_out = script.get("output", "").strip()
                if script_id and script_out:
                    scripts[script_id] = script_out

            svc = Service(
                port     = int(portid),
                protocol = port.get("protocol", "unknown"),
                state    = state_el.get("state", "unknown") if state_el is not None else "unknown",
                name     = svc_el.get("name", "")           if svc_el is not None else "",
                product  = svc_el.get("product", "")        if svc_el is not None else "",
                version  = svc_el.get("version", "")        if svc_el is not None else "",
                scripts  = scripts,
            )

            # Enrichissement version depuis les scripts si nmap n'a pas trouvé
            if not svc.version:
                svc.version = extract_version_from_scripts(svc.name, scripts)

            services.append(svc)
    return services

def extract_version_from_scripts(service_name: str, scripts: dict) -> str:
    """Tente d'extraire une version précise depuis les outputs NSE."""

    if "mysql-info" in scripts:
        for line in scripts["mysql-info"].splitlines():
            if "Version:" in line:
                return line.split("Version:")[-1].strip()

    if "vmware-version" in scripts:
        for line in scripts["vmware-version"].splitlines():
            if "Version" in line or "version" in line:
                return line.strip()

    if "http-server-header" in scripts:
        return scripts["http-server-header"].strip()

    if "ssl-cert" in scripts:
        for line in scripts["ssl-cert"].splitlines():
            if "commonName" in line:
                return line.strip()

    if "banner" in scripts:
        return scripts["banner"].strip()[:80]

    return ""

def print_results(services: list[Service]) -> None:
    print(f"\n{'PORT':<8} {'PROTO':<6} {'ÉTAT':<12} {'SERVICE':<16} {'PRODUIT/VERSION':<30} SCRIPTS NSE")
    print("-" * 100)
    for s in services:
        label = f"{s.product} {s.version}".strip()
        scripts_summary = " | ".join(
            f"{k}: {v[:40]}" for k, v in s.scripts.items()
        ) if s.scripts else ""
        print(f"{s.port:<8} {s.protocol:<6} {s.state:<12} {s.name:<16} {label:<30} {scripts_summary}")

def build_nse_args(services: list[Service]) -> list[str]:
    """Construit les args NSE à partir des services détectés au premier scan."""
    scripts_needed = set()
    for svc in services:
        for script in NSE_SCRIPTS.get(svc.name, []):
            scripts_needed.add(script)

    if not scripts_needed:
        return []

    return [f"--script={','.join(scripts_needed)}"]

def run_nmap(client, target: str, nmap_args: list[str]) -> str:
    output = client.containers.run(
        image        = DOCKER_IMAGE,
        command      = ["-oX", "-"] + nmap_args,
        remove       = True,
        network_mode = "host",
    )
    return output.decode("utf-8")

def main(args: dict) -> list[Service]:
    target  = args.get("target", "")
    options = args.get("options", [])

    if not target:
        print("[nmap] ERROR: No target provided.")
        return []

    options = options if isinstance(options, list) else [options]
    client  = docker.from_env()

    # --- Scan 1 : détection de services et versions ---
    scan1_args = [target] + options
    print(f"[nmap] Scan 1 — détection services : nmap {' '.join(scan1_args)}")
    xml1     = run_nmap(client, target, scan1_args)
    services = parse_xml(xml1)
    print_results(services)

    # --- Scan 2 : scripts NSE ciblés selon services trouvés ---
    nse_args = build_nse_args(services)
    if not nse_args:
        print("[nmap] Aucun script NSE applicable.")
        return services

    scan2_args = [target, "-sV"] + nse_args
    print(f"\n[nmap] Scan 2 — scripts NSE : nmap {' '.join(scan2_args)}")
    xml2          = run_nmap(client, target, scan2_args)
    services_nse  = parse_xml(xml2)

    # Merge : on enrichit les services du scan 1 avec les scripts du scan 2
    nse_map = {svc.port: svc for svc in services_nse}
    for svc in services:
        if svc.port in nse_map:
            nse_svc = nse_map[svc.port]
            svc.scripts = nse_svc.scripts
            if not svc.version and nse_svc.version:
                svc.version = nse_svc.version

    print("\n[nmap] Résultats enrichis :")
    print_results(services)
    return services

# ── PDF render hook (used by report_engine) ──────────────────────────────────
# Ajouter cette fonction à la fin de entry.py du module nmap.
# Le moteur de rapport l'appellera automatiquement si elle est définie.


def pdf_render(step: dict, module: dict, styles: dict, page_width: float):
    """
    Retourne une liste de Flowables ReportLab pour le rendu PDF du module nmap.
    Appelé par report_engine.generate_pdf() si la fonction est présente dans entry.py.
    """
    ports = step.get("output", []) or []

    if not ports:
        return [Paragraph("Aucun port ouvert détecté.", styles["small"])]

    C_ACCENT  = colors.HexColor("#00e5a0")
    C_MUTED   = colors.HexColor("#6b6b78")
    C_BG      = colors.HexColor("#0d0d0f")
    C_SURFACE = colors.HexColor("#141416")
    C_BORDER  = colors.HexColor("#2a2a2e")
    C_TEXT    = colors.HexColor("#e8e8ec")

    data = [["Port", "Proto", "Service", "Produit", "Version"]]
    for p in ports:
        port_val = p["port"] if isinstance(p, dict) else getattr(p, "port", "")
        proto    = (p.get("protocol", "") if isinstance(p, dict) else getattr(p, "protocol", "")).upper()
        name     = (p.get("name", "") if isinstance(p, dict) else getattr(p, "name", "")) or "—"
        product  = (p.get("product", "") if isinstance(p, dict) else getattr(p, "product", "")) or "—"
        version  = (p.get("version", "") if isinstance(p, dict) else getattr(p, "version", "")) or "—"
        data.append([
            Paragraph(f'<font color="#00e5a0"><b>{port_val}</b></font>', styles["mono"]),
            Paragraph(proto, styles["mono_mut"]),
            Paragraph(name, styles["body"]),
            Paragraph(product, styles["small"]),
            Paragraph(version, styles["mono_mut"]),
        ])  # type: ignore

    col_w = [18*mm, 14*mm, 32*mm, 55*mm, page_width - 119*mm]
    tbl = Table(data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_SURFACE),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_MUTED),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
        ("BACKGROUND",    (0, 1), (-1, -1), C_BG),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, colors.HexColor("#161618")]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return [tbl]