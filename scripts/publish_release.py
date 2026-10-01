"""Publish only checksum-verified assets from a version tag in GitHub Actions."""
from pathlib import Path
import hashlib,json,os,re,urllib.error,urllib.parse,urllib.request
from archive_sources import archive_sources

ROOT=Path(__file__).resolve().parents[1]

def sha256(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    repo=os.environ['GITHUB_REPOSITORY'];tag=os.environ['GITHUB_REF_NAME'];commit=os.environ['GITHUB_SHA']
    token=os.environ['GITHUB_TOKEN']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or not re.fullmatch(r'v\d+\.\d+\.\d+',tag):raise ValueError('Invalid release context')
    if not re.fullmatch(r'[0-9a-f]{40}',commit) or os.environ.get('GITHUB_REF_TYPE')!='tag':raise ValueError('Release requires a commit-backed version tag')
    version=tag[1:];assets=ROOT/'release-assets'/tag
    source_name='OpenVPNUI-Mac-'+version+'-Sources.zip'
    generated=ROOT/'dist'/source_name
    archive_sources(ROOT,generated)
    names={'OpenVPNUI-Mac-Intel-'+version+'.pkg','OpenVPNUI-Mac-Intel-'+version+'.app.zip',source_name}
    expected={}
    for line in (assets/'SHA256SUMS.txt').read_text().splitlines():
        digest,name=line.split('  ',1)
        if name not in names or name in expected or not re.fullmatch(r'[0-9a-f]{64}',digest):raise ValueError('Invalid asset manifest')
        expected[name]=digest
    if set(expected)!=names:raise ValueError('Incomplete asset manifest')
    files={name:(generated if name==source_name else assets/name) for name in sorted(names)}
    for name,path in files.items():
        if sha256(path)!=expected[name]:raise ValueError('Local checksum mismatch: '+name)
    files['SHA256SUMS.txt']=assets/'SHA256SUMS.txt'
    expected['SHA256SUMS.txt']=sha256(files['SHA256SUMS.txt'])

    def request(path,method='GET',data=None,url=None):
        destination=url or 'https://api.github.com/repos/'+repo+'/'+path
        if urllib.parse.urlparse(destination).hostname not in {'api.github.com','uploads.github.com'}:raise ValueError('Unexpected GitHub host')
        headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'OpenVPNUI-release'}
        if isinstance(data,dict):headers['Content-Type']='application/json';data=json.dumps(data).encode()
        elif data is not None:headers['Content-Type']='application/octet-stream'
        req=urllib.request.Request(destination,data=data,headers=headers,method=method)
        with urllib.request.urlopen(req,timeout=180) as response:return json.load(response)

    tag_object=request('git/ref/tags/'+tag)['object']
    if tag_object['type']=='tag':tag_object=request('git/tags/'+tag_object['sha'])['object']
    if tag_object['type']!='commit' or tag_object['sha']!=commit:raise ValueError('Remote tag does not match checked-out commit')
    try:release=request('releases/tags/'+tag)
    except urllib.error.HTTPError as error:
        if error.code!=404:raise
        release=request('releases',method='POST',data={'tag_name':tag,'target_commitish':commit,'name':'OpenVPNUI Mac '+version+' (Intel)','body':(ROOT/'RELEASE_NOTES.md').read_text(),'draft':True,'prerelease':False})
    for name,path in files.items():
        existing=next((a for a in release['assets'] if a['name']==name),None)
        if existing is None:
            if not release['draft']:raise ValueError('Existing public release is incomplete; refusing to modify it')
            print('Uploading '+name,flush=True)
            url=release['upload_url'].split('{',1)[0]+'?name='+urllib.parse.quote(name,safe='')
            request('',method='POST',data=path.read_bytes(),url=url)
            release=request('releases/'+str(release['id']))
        asset=next(a for a in release['assets'] if a['name']==name)
        if asset.get('state')!='uploaded' or asset.get('size')!=path.stat().st_size or asset.get('digest')!='sha256:'+expected[name]:
            raise ValueError('GitHub asset verification failed: '+name)
    if release['draft']:release=request('releases/'+str(release['id']),method='PATCH',data={'draft':False,'make_latest':'true'})
    if release['draft']:raise ValueError('Release remains a draft')
    print('Published and verified: '+release['html_url'],flush=True)

if __name__=='__main__':main()
