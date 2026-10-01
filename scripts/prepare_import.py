"""Convert a locally decrypted migration package; never prints profile secrets."""
import ipaddress, json, os, pathlib, shutil, sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
destination.mkdir(mode=0o700, parents=True, exist_ok=True)
profiles = json.loads((source / 'profiles.json').read_text(encoding='utf-8-sig'))
rules = []
for entry in json.loads((source / 'diagnostics/vpn-dns-policy.json').read_text(encoding='utf-8-sig')):
    domains, servers = entry['Namespace'], entry['NameServers']
    if isinstance(domains, dict): domains = domains['value']
    if isinstance(servers, dict): servers = servers['value']
    if isinstance(domains, str): domains = [domains]
    if isinstance(servers, str): servers = servers.replace(',', ' ').replace(';', ' ').split()
    servers = [str(ipaddress.IPv4Address(s['Address'].to_bytes(4, 'little'))) if isinstance(s, dict) and s['AddressFamily'] == 2 else s for s in servers]
    if not all(isinstance(s, str) for s in servers): raise ValueError('Unsupported DNS server serialization')
    if entry['DnsSecValidationRequired'] or entry['DirectAccessEnabled']:
        raise ValueError('DNSSEC / DirectAccess policy requires separate support')
    rules.append({'domains': sorted(set(s.lstrip('.').lower() for s in domains)), 'servers': servers})
merged, domain_servers = {}, {}
for rule in rules:
    key = tuple(sorted(set(rule['servers'])))
    for domain in rule['domains']:
        if domain in domain_servers and domain_servers[domain] != key:
            raise ValueError('Conflicting DNS rules in Windows snapshot')
        domain_servers[domain] = key
        merged.setdefault(key, set()).add(domain)
rules = [{'domains': sorted(domains), 'servers': list(servers)} for servers, domains in merged.items()]
store = {'profiles': [{'id': p['Id'], 'name': p['OriginalName'], 'configuration': (source / 'portable' / p['Id'] / 'client.ovpn').read_text(), 'dnsRules': [], 'useSnapshotDNS': False} for p in profiles], 'observedDNS': rules}
(destination / 'mac-profiles.json').write_text(json.dumps(store, ensure_ascii=False, indent=2))
os.chmod(destination / 'mac-profiles.json', 0o600)
for name in ['ca.pem', 'client.p12']:
    shutil.copyfile(source / 'certificates' / name, destination / name)
    os.chmod(destination / name, 0o600)
print('Prepared private import with', len(profiles), 'profiles and', len(rules), 'observed DNS rules.')
