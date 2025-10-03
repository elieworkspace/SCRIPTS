#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nmap_summary.py

Usage:
  python nmap_summary.py /chemin/vers/file.json

Sorties:
 - Imprime un résumé IP -> ports ouverts
 - Imprime un résumé Port -> IPs
 - Imprime (en JSON) un résumé key/value utile pour Red Team / SOC

Options (voir --help):
 - --top N    : n'affiche que les N premiers ports les plus fréquents
 - --critical : liste de ports critiques séparés par des virgules (ex: 22,80,443)
 - --json-out : n'affiche que le résumé key/value en JSON (pratique pour ingestion)
"""

import json
import argparse
import logging
import os
from collections import defaultdict, Counter
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def safe_get(d, *keys):
    """Descend dans un dictionnaire/objet en acceptant None ou clés manquantes."""
    cur = d
    for k in keys:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return None
    return cur


def ensure_list(x):
    """Retourne une liste si x est une liste, sinon enveloppe x dans une liste sauf si x est None."""
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def extract_hostname(host_entry):
    """Tente d'extraire hostname propre depuis host.hostnames qui peut être multiple/formatté."""
    # hostnames peut être None, dict {'hostname': {...}} ou string encodée
    hn = safe_get(host_entry, 'hostnames')
    if not hn:
        return None
    # Si hn a clé 'hostname'
    if isinstance(hn, dict) and 'hostname' in hn:
        val = hn['hostname']
        # val peut être list ou dict
        if isinstance(val, list):
            names = []
            for v in val:
                name = v.get('@name') if isinstance(v, dict) else None
                if name:
                    names.append(name)
            return names[0] if names else None
        if isinstance(val, dict):
            return val.get('@name')
    # Si hn est liste contenant dicts
    if isinstance(hn, list):
        for item in hn:
            if isinstance(item, dict) and 'hostname' in item:
                h = item['hostname']
                if isinstance(h, dict) and '@name' in h:
                    return h['@name']
    # dernier recours: si c'est str et semblant contenir un JSON encodé
    if isinstance(hn, str):
        try:
            parsed = json.loads(hn)
            if isinstance(parsed, dict) and 'hostname' in parsed:
                h = parsed['hostname']
                if isinstance(h, dict) and '@name' in h:
                    return h['@name']
        except Exception:
            pass
    return None


def iterate_hosts(nmapjson):
    """Récupère une liste d'objets host à partir du JSON nmaprun."""
    root = nmapjson.get('nmaprun') or nmapjson
    hosts = safe_get(root, 'host')
    if hosts is None:
        return []
    return ensure_list(hosts)


def extract_ports_from_host(host):
    """
    Extrait une liste de ports dicts: {'portid':..., 'protocol':..., 'state':..., 'service':..., 'service_product':..., 'cpe':..., 'script':[...] }
    """
    out = []
    ports_block = safe_get(host, 'ports')
    if ports_block is None:
        return out
    port_nodes = safe_get(ports_block, 'port')
    if port_nodes is None:
        return out
    for p in ensure_list(port_nodes):
        portid = safe_get(p, '@portid') or safe_get(p, 'portid')
        proto = safe_get(p, '@protocol') or safe_get(p, 'protocol')
        state_obj = safe_get(p, 'state') or {}
        state = safe_get(state_obj, '@state') or state_obj.get('@state') or state_obj.get('state') or None
        # service info
        svc = safe_get(p, 'service') or {}
        svc_name = svc.get('@name') if isinstance(svc, dict) else None
        svc_product = svc.get('@product') if isinstance(svc, dict) else None
        svc_version = svc.get('@version') if isinstance(svc, dict) else None
        cpe = svc.get('cpe') if isinstance(svc, dict) else None
        # scripts
        scripts = []
        script_node = safe_get(p, 'script')
        if script_node:
            for s in ensure_list(script_node):
                sid = s.get('@id') if isinstance(s, dict) else None
                sout = s.get('@output') if isinstance(s, dict) else None
                scripts.append({'id': sid, 'output': sout})
        out.append({
            'port': portid,
            'proto': proto,
            'state': state,
            'service': svc_name,
            'product': svc_product,
            'version': svc_version,
            'cpe': cpe,
            'scripts': scripts
        })
    return out


def extract_address(host):
    """Extrait l'adresse IP principale depuis host.address (prend le premier @addr)."""
    addr = safe_get(host, 'address')
    if addr is None:
        return None
    # addr peut être list ou dict
    candidates = ensure_list(addr)
    for a in candidates:
        if isinstance(a, dict) and a.get('@addr'):
            return a.get('@addr')
    return None


def summarize(nmapjson, critical_ports=None):
    hosts = iterate_hosts(nmapjson)
    ip_to_ports = defaultdict(list)   # ip -> list of (port/proto, state, service)
    port_to_ips = defaultdict(set)    # "80/tcp" -> set(ips)
    service_counter = Counter()
    port_counter = Counter()
    hosts_with_scripts = set()
    hosts_with_hostname = {}
    host_states = {'up': 0, 'other': 0}
    all_services = set()  # Nouvelle ligne pour collecter tous les services
    scan_start = safe_get(nmapjson.get('nmaprun') or nmapjson, '@start') or safe_get(nmapjson.get('nmaprun') or nmapjson, 'start')
    root_version = safe_get(nmapjson.get('nmaprun') or nmapjson, '@version') or None

    for h in hosts:
        ip = extract_address(h) or "<unknown>"
        hostname = extract_hostname(h)
        if hostname:
            hosts_with_hostname[ip] = hostname
        # status
        st = safe_get(h, 'status')
        state_val = None
        if isinstance(st, dict):
            state_val = st.get('@state') or st.get('state')
        if state_val and state_val.lower() == 'up':
            host_states['up'] += 1
        else:
            host_states['other'] += 1
        ports = extract_ports_from_host(h)
        for p in ports:
            key = f"{p['port']}/{p['proto'] or 'tcp'}"
            ip_to_ports[ip].append({
                'port': p['port'],
                'proto': p['proto'],
                'state': p['state'],
                'service': p['service'],
                'product': p['product'],
                'version': p['version'],
                'cpe': p['cpe'],
                'scripts': p['scripts']
            })
            port_counter[key] += 1
            if p['state'] and p['state'].lower() == 'open':
                port_to_ips[key].add(ip)
            if p['scripts']:
                hosts_with_scripts.add(ip)
            if p['service']:
                service_counter[p['service']] += 1
                all_services.add(p['service'])  # Nouvelle ligne pour ajouter le service à la liste complète

    # prepare outputs
    # IP -> ports (only ports that are open + state)
    ip_ports_simple = {}
    for ip, lst in ip_to_ports.items():
        # sort by port number int if possible
        def sort_key(x):
            try:
                return int(x['port'])
            except Exception:
                return 0
        lst_sorted = sorted(lst, key=sort_key)
        ip_ports_simple[ip] = [{
            'port_proto': f"{item['port']}/{item['proto'] or 'tcp'}",
            'state': item['state'],
            'service': item['service']
        } for item in lst_sorted]

    # Port -> IPs (only IPs that had state open)
    port_ips_simple = {port: sorted(list(ips)) for port, ips in port_to_ips.items()}

    # Red Team / SOC key-values
    total_hosts = len(list(ip_to_ports.keys()))
    total_hosts_up = host_states['up']
    unique_ports = len(port_counter)
    most_common_ports = port_counter.most_common(10)
    most_common_services = service_counter.most_common(10)
    hosts_with_scripts_list = sorted(list(hosts_with_scripts))
    hosts_with_hostname_list = hosts_with_hostname  # dict ip->hostname

    critical_list = []
    if critical_ports:
        for cp in critical_ports:
            key = f"{cp}/tcp"
            ips = port_to_ips.get(key, set()) | port_to_ips.get(f"{cp}/udp", set())
            if ips:
                critical_list.append({'port': cp, 'ips': sorted(list(ips))})

    summary = {
        'scan_start': scan_start,
        'nmap_version': root_version,
        'total_hosts_seen': total_hosts,
        'hosts_up': total_hosts_up,
        'unique_ports_count': unique_ports,
        'top_ports': [{'port': p, 'count': c} for p, c in most_common_ports],
        'top_services': [{'service': s, 'count': c} for s, c in most_common_services],
        'all_services_found': sorted(list(all_services)),  # Nouvelle ligne avec la liste complète des services
        'hosts_with_script_output_count': len(hosts_with_scripts),
        'hosts_with_script_output': hosts_with_scripts_list,
        'hosts_with_hostname': hosts_with_hostname_list,
        'critical_ports_summary': critical_list
    }

    return ip_ports_simple, port_ips_simple, summary


def main():
    parser = argparse.ArgumentParser(description="Résumé Nmap JSON: IP->ports, Port->IP, résumé clé/valeur pour Red Team/SOC")
    parser.add_argument("json_file", help="Fichier JSON export Nmap (structure nmaprun)")
    parser.add_argument("--top", type=int, default=0, help="Afficher seulement les N ports les plus fréquents (0 = tous)")
    parser.add_argument("--critical", type=str, default="", help="Liste de ports critiques séparés par des virgules ex: 22,80,3389")
    parser.add_argument("--json-out-only", action="store_true", help="Afficher seulement le résumé key/value (JSON)")
    parser.add_argument("--save-json", type=str, default="", help="Sauvegarder le résumé JSON: chemin de dossier (nom auto) ou chemin de fichier complet")
    args = parser.parse_args()

    if not os.path.isfile(args.json_file):
        logging.error("Fichier non trouvé: %s", args.json_file)
        return

    with open(args.json_file, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception as e:
            logging.error("Erreur lecture JSON: %s", e)
            return

    critical_ports = []
    if args.critical:
        for p in args.critical.split(','):
            p = p.strip()
            if p:
                try:
                    critical_ports.append(int(p))
                except:
                    pass

    ip_ports, port_ips, summary = summarize(data, critical_ports=critical_ports)

    # Sauvegarder le résumé JSON si l'option --save-json est utilisée
    if args.save_json:
        try:
            save_path = args.save_json
            
            # Si c'est un dossier, générer automatiquement le nom de fichier
            if os.path.isdir(save_path) or (not os.path.exists(save_path) and not save_path.endswith('.json')):
                # Créer le dossier s'il n'existe pas
                os.makedirs(save_path, exist_ok=True)
                
                # Générer le nom de fichier automatiquement
                now = datetime.now()
                existing_json_files = [f for f in os.listdir(save_path) if f.endswith('.json')]
                filename = f"{len(existing_json_files)+1}_{now.strftime('%Y%m%d%H%M%S%f')[:-3]}.json"
                save_path = os.path.join(save_path, filename)
            
            # Sauvegarder le fichier
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            logging.info(f"Résumé JSON sauvegardé dans: {save_path}")
        except Exception as e:
            logging.error(f"Erreur lors de la sauvegarde JSON: {e}")

    if args.json_out_only:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return

    # Print IP -> ports
    print("=== IP -> ports (liste triée) ===")
    for ip, ports in sorted(ip_ports.items()):
        open_ports = [p for p in ports if p['state'] and p['state'].lower() == 'open']
        print(f"{ip}:")
        if not ports:
            print("  (pas de ports listés)")
            continue
        for p in ports:
            mark = "*" if p['state'] and p['state'].lower() == 'open' else " "
            svc = f" [{p['service']}]" if p['service'] else ""
            print(f"  {mark} {p['port_proto']:10} {p['state']:6}{svc}")
    print()

    # Print Port -> IPs
    print("=== Port -> IPs (only IPs with port open) ===")
    # optionally apply top filter
    port_counts = sorted([(port, len(ips)) for port, ips in port_ips.items()], key=lambda x: -x[1])
    if args.top > 0:
        port_counts = port_counts[:args.top]
    for port, cnt in port_counts:
        ips = sorted(list(port_ips.get(port, [])))
        print(f"{port} ({cnt} hosts): {', '.join(ips)}")
    print()

    # Print summary key/value JSON
    print("=== Résumé clé/valeur (JSON) ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
