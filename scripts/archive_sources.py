from pathlib import Path
import zipfile,hashlib,sys

def archive_sources(root, output):
    root=Path(root).resolve();output=Path(output).resolve();output.parent.mkdir(parents=True,exist_ok=True)
    names=(root/'SOURCE_FILES.txt').read_text().splitlines()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            relative=Path(name)
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe source manifest path')
            source=root/relative
            if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(root):raise ValueError('Source manifest file missing or unsafe: '+name)
            archive.write(source,'OpenVPNUI-Mac/'+name)
    with output.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    destination=Path(sys.argv[1]) if len(sys.argv)>1 else root/'dist/OpenVPNUI-Mac-0.2.1-Sources.zip'
    print(archive_sources(root,destination)+'  '+destination.name)
