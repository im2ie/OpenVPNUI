from pathlib import Path
import subprocess,tempfile,json,datetime,os,sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from cryptography.hazmat.primitives.serialization import pkcs12

tool=Path(sys.argv[1] if len(sys.argv) > 1 else 'build/p12tool').resolve()
openssl=str(Path(os.environ.get('OPENSSL_PREFIX','/usr/local/opt/openssl@3'))/'bin/openssl')
with tempfile.TemporaryDirectory(prefix='openvpn-crypto-test-') as name:
 root=Path(name);os.chmod(root,0o700)
 def call(args, passwords=[], expected=0):
  r=subprocess.run([str(tool),*map(str,args)],input=('\n'.join(passwords)+'\n').encode(),capture_output=True,timeout=90)
  assert r.returncode==expected,(args[0],r.returncode)
  return r.stdout
 now=datetime.datetime.now(datetime.timezone.utc)
 ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Offline Test CA')])
 ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True).sign(ca_key,hashes.SHA256()))
 ca_file=root/'ca.pem';ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
 for algo in ['RSA4096','ECDSA_P384']:
  key=root/(algo+'.key');csr=root/(algo+'.csr');p12=root/(algo+'.p12');response=root/(algo+'.pem')
  call(['--csr',key,csr,algo,'Test Client','','','Test City','','UA','test@example.test'],['request-test-password'])
  request=x509.load_pem_x509_csr(csr.read_bytes());assert request.is_signature_valid
  assert ExtendedKeyUsageOID.CLIENT_AUTH in request.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
  cert=(x509.CertificateBuilder().subject_name(request.subject).issuer_name(ca_name).public_key(request.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(days=10)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False).sign(ca_key,hashes.SHA256()))
  response.write_bytes(cert.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM))
  call(['--complete',response,key,p12],['request-test-password','p12-test-password'])
  record=json.loads(call(['--inspect',p12],['p12-test-password']))
  assert record['hasPrivateKey'] and record['bits']==(4096 if algo=='RSA4096' else 384)
  assert 'PRIVATE KEY' not in json.dumps(record)
  call(['--matches-ca',p12,ca_file],['p12-test-password'])
  call(['--matches-cert-ca',response,ca_file])
  public=json.loads(call(['--inspect-cert',response]));assert not public['hasPrivateKey'] and len(public['chain'])==1
  call(['--inspect',p12],['wrong-password'],expected=6)
  new=root/(algo+'-changed.p12');call(['--protect',p12,new],['p12-test-password','changed-password'])
  changed=json.loads(call(['--inspect',new],['changed-password']));assert changed['sha256']==record['sha256']
  call(['--protect',p12,root/(algo+'-short.p12')],['p12-test-password','short'],expected=4)
  call(['--protect',p12,new],['p12-test-password','changed-password'],expected=9)
  assert (key.stat().st_mode&0o777)==0o600 and (p12.stat().st_mode&0o777)==0o600
  private=serialization.load_pem_private_key(key.read_bytes(),b'request-test-password')
  blank=root/(algo+'-blank.p12');blank.write_bytes(pkcs12.serialize_key_and_certificates(b'test',private,cert,[ca],serialization.NoEncryption()))
  protected=root/(algo+'-protected.p12');call(['--protect',blank,protected],['','protected-password'])
  assert json.loads(call(['--inspect',protected],['protected-password']))['sha256']==record['sha256']
  # Response with a different key must not be accepted for this request.
  call(['--complete',ca_file,key,root/(algo+'-mismatch.p12')],['request-test-password','p12-test-password'],expected=17)
  if algo=='RSA4096':
   passfile=root/'test-password';passfile.write_text('request-test-password\n');os.chmod(passfile,0o600)
   legacy=root/'legacy.pfx';outpass=root/'export-password';outpass.write_bytes(passfile.read_bytes());os.chmod(outpass,0o600)
   made=subprocess.run([openssl,'pkcs12','-export','-legacy','-inkey',str(key),'-in',str(response),'-out',str(legacy),'-passin','file:'+str(passfile),'-passout','file:'+str(outpass)],capture_output=True)
   assert made.returncode==0, made.stderr.decode()
   converted=root/'legacy-protected.p12';call(['--protect',legacy,converted],['request-test-password','protected-password'])
   assert json.loads(call(['--inspect',converted],['protected-password']))['sha256']==record['sha256']
   print('PASS: legacy Windows PFX (RC2/3DES) imports using bundled provider')
  print('PASS:',algo,'CSR, encrypted key, signed response, CA matching, P12 conversion, wrong password, permissions, wrong-key rejection')
print('PASS: all crypto tests used synthetic certificates; no network connection')
