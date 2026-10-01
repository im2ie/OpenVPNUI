from pathlib import Path
import hashlib
root=Path(__file__).resolve().parents[1]/'upstream'
for line in (root/'SHA256SUMS.txt').read_text().splitlines():
 digest,name=line.split('  ',1)
 assert Path(name).name==name
 with (root/name).open('rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
 if actual!=digest:raise SystemExit('Source archive checksum mismatch: '+name)
print('PASS: upstream archive checksums')
