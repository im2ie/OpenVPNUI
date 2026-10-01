from pathlib import Path
import shutil,subprocess,sys
source=Path(sys.argv[1]); target=Path(sys.argv[2]);target.mkdir(parents=True,exist_ok=True)
for src,dst in [(source/'lib/ossl-modules/legacy.dylib',target/'legacy.dylib'),(source/'lib/libcrypto.3.dylib',target/'libcrypto.3.dylib')]:
 if dst.exists():dst.chmod(0o755)
 shutil.copy2(src,dst);dst.chmod(0o755)
module=target/'legacy.dylib'
lines=subprocess.check_output(['otool','-L',str(module)],text=True).splitlines()[1:]
for line in lines:
 dependency=line.strip().split(' (')[0]
 if dependency.endswith('/libcrypto.3.dylib'):
  subprocess.run(['install_name_tool','-change',dependency,'@loader_path/libcrypto.3.dylib',str(module)],check=True)
subprocess.run(['install_name_tool','-id','@loader_path/libcrypto.3.dylib',str(target/'libcrypto.3.dylib')],check=True)
