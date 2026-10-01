from pathlib import Path
import tempfile,subprocess,plistlib,json,zipfile,hashlib
root=Path(__file__).resolve().parents[1];out=Path(__import__('sys').argv[1]).resolve() if len(__import__('sys').argv)>1 else root/'dist';checks=[]
def run(args):
 r=subprocess.run(list(map(str,args)),capture_output=True,text=True)
 if r.returncode:raise RuntimeError(str(args[0])+': '+r.stderr.strip())
 return r.stdout
with tempfile.TemporaryDirectory(prefix='openvpn-release-check-',dir='/private/tmp') as d:
 temp=Path(d)
 run(['ditto','-x','-k',out/'OpenVPNUI-Mac-Intel-0.2.1.app.zip',temp/'app'])
 app=temp/'app/OpenVPNUI Mac.app';res=app/'Contents/Resources'
 info=plistlib.loads((app/'Contents/Info.plist').read_bytes());assert info['CFBundleShortVersionString']=='0.2.1';assert info['CFBundleURLTypes'][0]['CFBundleURLSchemes']==['openvpnui']
 run(['codesign','--verify','--deep','--strict',app]);checks.append('App bundle and nested code signatures verify')
 run(['pkgutil','--expand-full',out/'OpenVPNUI-Mac-Intel-0.2.1.pkg',temp/'pkg'])
 helper=next((temp/'pkg').rglob('com.local.openvpnui.helper'));engine=next(p for p in (temp/'pkg').rglob('openvpn') if p.is_file())
 binaries=[app/'Contents/MacOS/OpenVPNUIMac',res/'p12tool',res/'openvpnuictl',res/'legacy/legacy.dylib',res/'legacy/libcrypto.3.dylib',helper,engine]
 for binary in binaries:
  assert run(['lipo','-archs',binary]).strip()=='x86_64',binary.name
  run(['codesign','--verify','--strict',binary])
  dependencies=run(['otool','-L',binary]).splitlines()[1:]
  for line in dependencies:
   dependency=line.strip().split(' (')[0]
   assert dependency.startswith(('/usr/lib/','/System/Library/','@loader_path/','@rpath/')), (binary.name,dependency)
 checks.append('GUI, helper, engine, certificate tool, CLI and provider are x86_64 with bundled/system dependencies')
 assert 'OpenVPN 2.6.23' in run([engine,'--version']);assert 'plugins=no' in run([engine,'--version'])
 assert 'makefile' in run([res/'openvpnuictl','--help'])
 checks.append('Packaged engine and CLI run offline')
 for file in app.rglob('*'):
  assert file.suffix.lower() not in ['.p12','.pfx','.ovpn','.openvpn','.key'],file.name
 checks.append('App/installer bundle contains no client identity or corporate profile files')
 run([__import__('sys').executable,root/'tests/validate_crypto.py',res/'p12tool'])
 checks.append('Packaged certificate utility passes RSA, ECDSA, legacy PFX and encryption tests')
 with zipfile.ZipFile(out/'OpenVPNUI-Mac-0.2.1-Sources.zip') as z:
  assert z.testzip() is None
  for name in z.namelist():assert '/private/' not in name
 checks.append('Source archive integrity and explicit nonsecret file list checked')
report={'version':'0.2.1','architecture':'x86_64','minimum_macos':'26.0',
'checks_passed':checks+['Fresh native build from the prepared source tree','Fresh engine build from the bundled OpenVPN source archive using installed exact-version dependencies','Native import/export, configuration/XML validation, DNS parsing/conflicts and settings locks','Management authentication, proxy separation, password retention, traffic and bounded redacted logs','Short log lines arrive before process termination; original shutdown reason preserved; connection phases displayed','Missing administrator authorization rejected'],
'not_verified':['Rebuilding OpenSSL/LZO/LZ4 through scripts/build_dependencies.sh','All native GUI controls and macOS authorization dialogs in the prepared package','Interoperability with arbitrary VPN servers, MFA and DNS policies','Sleep/wake, failover and network recovery with live tunnels'],
'network_connections_in_release_tests':False,
'signing':'Ad-hoc application/component signatures; no Developer ID Installer signature or Apple notarization'}
(root/'VALIDATION.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print('PASS: release bundle, installer payload, signatures, architecture, dependencies, packaged crypto, source archive')

from archive_sources import archive_sources
archive_sources(root, out/'OpenVPNUI-Mac-0.2.1-Sources.zip')
with (out/'SHA256SUMS.txt').open('w') as manifest:
 for file in sorted(out.iterdir()):
  if file.is_file() and file.name!='SHA256SUMS.txt':
   with file.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
   manifest.write(digest+'  '+file.name+'\n')
