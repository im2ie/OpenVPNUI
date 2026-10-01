import os, pathlib, plistlib, shutil, subprocess, tempfile, zipfile, argparse

root = pathlib.Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description='Package the Intel application and complete source archive locally.')
parser.add_argument('--build-dir', type=pathlib.Path, default=root/'build')
parser.add_argument('--engine', type=pathlib.Path)
parser.add_argument('--output', type=pathlib.Path, default=root/'dist')
args = parser.parse_args()
build = args.build_dir.resolve()
engine_binary = (args.engine or build/'openvpn').resolve()
out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
stage = pathlib.Path(tempfile.mkdtemp(prefix='openvpnui-stage-',dir='/private/tmp'))
app = stage/'Applications/OpenVPNUI Mac.app'
resources = app/'Contents/Resources'
resources.mkdir(parents=True)
(app/'Contents/MacOS').mkdir()
shutil.copy2(build/'OpenVPNUIMac', app/'Contents/MacOS/OpenVPNUIMac')
shutil.copy2(build/'p12tool', resources/'p12tool')
shutil.copy2(build/'openvpnuictl', resources/'openvpnuictl')
shutil.copytree(build/'legacy', resources/'legacy')
with (app/'Contents/Info.plist').open('wb') as f:
    plistlib.dump({'CFBundleIdentifier':'com.local.openvpnui.mac','CFBundleName':'OpenVPNUI Mac','CFBundleDisplayName':'OpenVPNUI Mac','CFBundleExecutable':'OpenVPNUIMac','CFBundlePackageType':'APPL','CFBundleShortVersionString':'0.2.2','CFBundleVersion':'4','CFBundleDevelopmentRegion':'en','CFBundleLocalizations':['en','ru'],'LSMinimumSystemVersion':'26.0','NSHighResolutionCapable':True,'CFBundleIconFile':'AppIcon','CFBundleURLTypes':[{'CFBundleURLName':'OpenVPNUI Connection','CFBundleURLSchemes':['openvpnui']}],'CFBundleDocumentTypes':[{'CFBundleTypeName':'OpenVPN profile','CFBundleTypeRole':'Editor','CFBundleTypeExtensions':['openvpn','ovpn','conf','connection']}]}, f)
icon = root/'resources/AppIcon.icns'
if icon.exists(): shutil.copy2(icon, resources/'AppIcon.icns')
engine = stage/'Library/Application Support/OpenVPNUI Mac/Engine'
engine.mkdir(parents=True)
shutil.copy2(engine_binary,engine/'openvpn')
lic = engine.parent/'Licenses';lic.mkdir()
for source in (root/'licenses').iterdir(): shutil.copy2(source,lic/source.name)
shutil.copytree(lic,resources/'Licenses')
helper = stage/'Library/PrivilegedHelperTools/com.local.openvpnui.helper'
helper.parent.mkdir(parents=True);shutil.copy2(build/'helper',helper)
jobs = stage/'Library/LaunchDaemons';jobs.mkdir()
with (jobs/'com.local.openvpnui.helper.plist').open('wb') as f:
    plistlib.dump({'Label':'com.local.openvpnui.helper','ProgramArguments':['/Library/PrivilegedHelperTools/com.local.openvpnui.helper'],'RunAtLoad':True,'KeepAlive':True,'AbandonProcessGroup':False,'ProcessType':'Background','ThrottleInterval':5,'Umask':63,'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null'},f)
for path in stage.rglob('*'):
    if path.is_dir(): os.chmod(path,0o755)
for path in [helper,engine/'openvpn',resources/'p12tool',resources/'openvpnuictl',resources/'legacy/libcrypto.3.dylib',resources/'legacy/legacy.dylib',app/'Contents/MacOS/OpenVPNUIMac']: os.chmod(path,0o755)
for path in (root/'packaging').iterdir(): os.chmod(path,0o755)
subprocess.run(['xattr','-cr',str(stage)],check=True)
# Drop debug/STABS source paths before signing distributed Mach-O files.
for path in [engine/'openvpn',helper,resources/'legacy/libcrypto.3.dylib',resources/'legacy/legacy.dylib',resources/'p12tool',resources/'openvpnuictl',app/'Contents/MacOS/OpenVPNUIMac']:
    subprocess.run(['strip','-S',str(path)],check=True,capture_output=True)
for path in [engine/'openvpn',helper,resources/'legacy/libcrypto.3.dylib',resources/'legacy/legacy.dylib',resources/'p12tool',resources/'openvpnuictl']:
    subprocess.run(['codesign','--force','--sign','-','--timestamp=none',str(path)],check=True,capture_output=True)
subprocess.run(['codesign','--force','--sign','-','--timestamp=none',str(app)],check=True,capture_output=True)
# Output is an explicit, separate directory.
subprocess.run(['ditto','--norsrc','--noextattr','-c','-k','--keepParent',str(app),str(out/'OpenVPNUI-Mac-Intel-0.2.2.app.zip')],check=True)
components = stage.parent/(stage.name+'-components.plist')
with components.open('wb') as f: plistlib.dump([{'RootRelativeBundlePath':'Applications/OpenVPNUI Mac.app','BundleIsRelocatable':False,'BundleHasStrictIdentifier':True,'BundleIsVersionChecked':True,'BundleOverwriteAction':'upgrade'}],f)
subprocess.run(['pkgbuild','--root',str(stage),'--component-plist',str(components),'--scripts',str(root/'packaging'),'--identifier','com.local.openvpnui.mac.installer','--version','0.2.2','--install-location','/','--ownership','recommended',str(out/'OpenVPNUI-Mac-Intel-0.2.2.pkg')],check=True)
from scripts.archive_sources import archive_sources
archive_sources(root, out/'OpenVPNUI-Mac-0.2.2-Sources.zip')
components.unlink()
print('Created app, installer and sources; no corporate certificates or profile secrets included.')
shutil.rmtree(stage)
