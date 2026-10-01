#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <mach-o/dyld.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static char password1[4098], password2[4098];
static int passwords(int two) {
    if (!fgets(password1,sizeof(password1),stdin)) return 0;
    password1[strcspn(password1,"\r\n")]=0;
    if (two) { if (!fgets(password2,sizeof(password2),stdin)) return 0; password2[strcspn(password2,"\r\n")]=0; }
    return 1;
}
static void cleanup(void) { OPENSSL_cleanse(password1,sizeof(password1)); OPENSSL_cleanse(password2,sizeof(password2)); }
static FILE *output(const char *path) { int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);return fd<0?NULL:fdopen(fd,"wb"); }
static void json(const char *s) {
    putchar('"'); for (const unsigned char *p=(const unsigned char *)s; *p; p++) { if (*p=='"'||*p=='\\') printf("\\%c",*p); else if (*p<32) printf("\\u%04x",*p); else putchar(*p); } putchar('"');
}
static char *bio_text(BIO *b) { char *p=NULL;long n=BIO_get_mem_data(b,&p);char *s=OPENSSL_malloc(n+1);memcpy(s,p,n);s[n]=0;return s; }
static char *name_text(X509_NAME *name) { BIO *b=BIO_new(BIO_s_mem());X509_NAME_print_ex(b,name,0,XN_FLAG_RFC2253);char *s=bio_text(b);BIO_free(b);return s; }
static void fingerprint(X509 *cert,const EVP_MD *digest,char *out) { unsigned char bytes[EVP_MAX_MD_SIZE];unsigned int n=0;X509_digest(cert,digest,bytes,&n);for(unsigned i=0;i<n;i++)sprintf(out+2*i,"%02X",bytes[i]);out[2*n]=0; }
static char *certificate_pem(X509 *cert) { BIO *b=BIO_new(BIO_s_mem());PEM_write_bio_X509(b,cert);char *s=bio_text(b);BIO_free(b);return s; }
static void print_time(const ASN1_TIME *time) { BIO *b=BIO_new(BIO_s_mem());ASN1_TIME_print(b,time);char *s=bio_text(b);json(s);OPENSSL_free(s);BIO_free(b); }
static void inspect(X509 *cert, EVP_PKEY *key, STACK_OF(X509) *chain) {
    char sha1[EVP_MAX_MD_SIZE*2+1],sha256[EVP_MAX_MD_SIZE*2+1],cn[1024]={0};fingerprint(cert,EVP_sha1(),sha1);fingerprint(cert,EVP_sha256(),sha256);
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert),NID_commonName,cn,sizeof(cn));
    char *subject=name_text(X509_get_subject_name(cert)),*issuer=name_text(X509_get_issuer_name(cert)),*pem=certificate_pem(cert);EVP_PKEY *pub=X509_get_pubkey(cert);
    printf("{\"id\":");json(sha256);printf(",\"name\":");json(cn);printf(",\"subject\":");json(subject);printf(",\"issuer\":");json(issuer);printf(",\"sha1\":");json(sha1);printf(",\"sha256\":");json(sha256);
    printf(",\"notBefore\":");print_time(X509_get0_notBefore(cert));printf(",\"notAfter\":");print_time(X509_get0_notAfter(cert));printf(",\"algorithm\":");json(EVP_PKEY_get0_type_name(pub));printf(",\"bits\":%d,\"hasPrivateKey\":%s,\"generatedPassword\":false,\"certificate\":",EVP_PKEY_get_bits(pub),key?"true":"false");json(pem);printf(",\"chain\":[");
    for (int i=0;chain&&i<sk_X509_num(chain);i++){char *text=certificate_pem(sk_X509_value(chain,i));if(i)putchar(',');json(text);OPENSSL_free(text);}printf("]}\n");
    EVP_PKEY_free(pub);OPENSSL_free(subject);OPENSSL_free(issuer);OPENSSL_free(pem);
}
static STACK_OF(X509) *read_certificates(const char *path) {
    BIO *b=BIO_new_file(path,"rb");if(!b)return NULL;STACK_OF(X509)*result=sk_X509_new_null();X509 *c;
    while((c=PEM_read_bio_X509(b,NULL,NULL,NULL)))sk_X509_push(result,c);
    if(sk_X509_num(result)==0){BIO_reset(b);c=d2i_X509_bio(b,NULL);if(c)sk_X509_push(result,c);}
    if(sk_X509_num(result)==0){BIO_reset(b);PKCS7*p=PEM_read_bio_PKCS7(b,NULL,NULL,NULL);if(!p){BIO_reset(b);p=d2i_PKCS7_bio(b,NULL);}if(p&&PKCS7_type_is_signed(p)){STACK_OF(X509)*certs=p->d.sign->cert;for(int i=0;certs&&i<sk_X509_num(certs);i++)sk_X509_push(result,X509_dup(sk_X509_value(certs,i)));}PKCS7_free(p);}
    BIO_free(b);ERR_clear_error();if(!sk_X509_num(result)){sk_X509_free(result);return NULL;}return result;
}
static int read_p12(const char *path,EVP_PKEY **key,X509 **cert,STACK_OF(X509)**chain) {
    FILE *in=fopen(path,"rb");if(!in)return 0;PKCS12*p=d2i_PKCS12_fp(in,NULL);fclose(in);int ok=p&&PKCS12_parse(p,password1,key,cert,chain);PKCS12_free(p);return ok&&*key&&*cert&&X509_check_private_key(*cert,*key)==1;
}
static int write_p12(const char *path,EVP_PKEY *key,X509 *cert,STACK_OF(X509)*chain) {
    if(strlen(password2)<8)return 4;
    PKCS12*p=PKCS12_create(password2,"OpenVPNUI Mac",key,cert,chain,NID_aes_256_cbc,NID_aes_256_cbc,100000,100000,0);if(!p)return 8;
    FILE*out=output(path);if(!out){PKCS12_free(p);return 9;}int ok=i2d_PKCS12_fp(out,p);fclose(out);PKCS12_free(p);if(!ok){unlink(path);return 10;}return 0;
}
static int create_csr(int argc,char**argv) {
    if(argc!=12||!passwords(0)||strlen(password1)<8)return 2;
    EVP_PKEY *key=NULL;EVP_PKEY_CTX *ctx=NULL;
    if(!strcmp(argv[4],"RSA4096")){ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);if(!ctx||EVP_PKEY_keygen_init(ctx)<=0||EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,4096)<=0||EVP_PKEY_keygen(ctx,&key)<=0)return 11;}
    else if(!strcmp(argv[4],"ECDSA_P384")){ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);if(!ctx||EVP_PKEY_keygen_init(ctx)<=0||EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,NID_secp384r1)<=0||EVP_PKEY_keygen(ctx,&key)<=0)return 11;}
    else return 2;
    EVP_PKEY_CTX_free(ctx);X509_REQ *req=X509_REQ_new();X509_REQ_set_version(req,0);X509_REQ_set_pubkey(req,key);X509_NAME *name=X509_NAME_new();
    const char *fields[]={"CN","O","OU","L","ST","C","emailAddress"};for(int i=0;i<7;i++){if(!strlen(argv[i+5]))continue;if(strlen(argv[i+5])>512||!X509_NAME_add_entry_by_txt(name,fields[i],MBSTRING_UTF8,(unsigned char*)argv[i+5],-1,-1,0))return 12;}
    X509_REQ_set_subject_name(req,name);X509_NAME_free(name);
    STACK_OF(X509_EXTENSION)*exts=sk_X509_EXTENSION_new_null();
    X509_EXTENSION *usage=X509V3_EXT_conf_nid(NULL,NULL,NID_key_usage,"digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment");X509_EXTENSION*eku=X509V3_EXT_conf_nid(NULL,NULL,NID_ext_key_usage,"clientAuth");
    sk_X509_EXTENSION_push(exts,usage);sk_X509_EXTENSION_push(exts,eku);X509_REQ_add_extensions(req,exts);sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
    if(X509_REQ_sign(req,key,EVP_sha384())<=0)return 13;
    FILE*k=output(argv[2]);if(!k)return 9;int ok=PEM_write_PKCS8PrivateKey(k,key,EVP_aes_256_cbc(),password1,(int)strlen(password1),NULL,NULL);fclose(k);if(!ok){unlink(argv[2]);return 14;}
    FILE*c=output(argv[3]);if(!c){unlink(argv[2]);return 9;}ok=PEM_write_X509_REQ(c,req);fclose(c);X509_REQ_free(req);EVP_PKEY_free(key);if(!ok){unlink(argv[2]);unlink(argv[3]);return 15;}return 0;
}
int main(int argc,char**argv) {
    atexit(cleanup);if(argc<3)return 2;
    char executable[PATH_MAX],resolved[PATH_MAX],modulepath[PATH_MAX];uint32_t size=sizeof(executable);
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG,NULL);
    OSSL_PROVIDER_load(NULL,"default");
    if(_NSGetExecutablePath(executable,&size)==0&&realpath(executable,resolved)) {
        char*slash=strrchr(resolved,'/');if(slash){*slash=0;snprintf(modulepath,sizeof(modulepath),"%s/legacy",resolved);OSSL_PROVIDER_set_default_search_path(NULL,modulepath);OSSL_PROVIDER_load(NULL,"legacy");ERR_clear_error();}
    }
    if(!strcmp(argv[1],"--csr"))return create_csr(argc,argv);
    if(!strcmp(argv[1],"--inspect-cert")) { STACK_OF(X509)*certs=read_certificates(argv[2]);if(!certs)return 5;X509*leaf=sk_X509_shift(certs);inspect(leaf,NULL,certs);X509_free(leaf);sk_X509_pop_free(certs,X509_free);return 0; }
    if(!strcmp(argv[1],"--matches-cert-ca")) {
        if(argc!=4)return 2;STACK_OF(X509)*all=read_certificates(argv[2]),*cas=read_certificates(argv[3]);if(!all||!cas)return 5;
        X509*leaf=sk_X509_shift(all);X509_STORE*store=X509_STORE_new();for(int i=0;i<sk_X509_num(cas);i++)X509_STORE_add_cert(store,sk_X509_value(cas,i));
        X509_STORE_CTX*ctx=X509_STORE_CTX_new();X509_STORE_CTX_init(ctx,store,leaf,all);X509_STORE_CTX_set_purpose(ctx,X509_PURPOSE_SSL_CLIENT);
        int result=X509_verify_cert(ctx)==1?0:16;X509_STORE_CTX_free(ctx);X509_STORE_free(store);X509_free(leaf);sk_X509_pop_free(all,X509_free);sk_X509_pop_free(cas,X509_free);return result;
    }
    EVP_PKEY *key=NULL;X509 *cert=NULL;STACK_OF(X509)*chain=NULL;int code=0;
    if(!strcmp(argv[1],"--protect")||!strcmp(argv[1],"--inspect")||!strcmp(argv[1],"--matches-ca")){
        int convert=!strcmp(argv[1],"--protect");if(!passwords(convert)||!read_p12(argv[2],&key,&cert,&chain))return 6;
        if(convert){if(argc!=4)return 2;code=write_p12(argv[3],key,cert,chain);}
        else if(!strcmp(argv[1],"--inspect"))inspect(cert,key,chain);
        else {if(argc!=4)return 2;STACK_OF(X509)*cas=read_certificates(argv[3]);if(!cas)return 5;X509_STORE*store=X509_STORE_new();for(int i=0;i<sk_X509_num(cas);i++)X509_STORE_add_cert(store,sk_X509_value(cas,i));X509_STORE_CTX*ctx=X509_STORE_CTX_new();X509_STORE_CTX_init(ctx,store,cert,chain);X509_STORE_CTX_set_purpose(ctx,X509_PURPOSE_SSL_CLIENT);code=X509_verify_cert(ctx)==1?0:16;X509_STORE_CTX_free(ctx);X509_STORE_free(store);sk_X509_pop_free(cas,X509_free);}
    }else if(!strcmp(argv[1],"--import-pem")||!strcmp(argv[1],"--complete")) {
        if(argc!=5||!passwords(1))return 2;FILE*f=fopen(argv[3],"rb");if(!f)return 5;key=PEM_read_PrivateKey(f,NULL,NULL,password1);fclose(f);if(!key)return 6;
        STACK_OF(X509)*all=read_certificates(argv[2]);if(!all)return 5;chain=sk_X509_new_null();
        for(int i=0;i<sk_X509_num(all);i++){X509*c=sk_X509_value(all,i);if(!cert&&X509_check_private_key(c,key)==1)cert=X509_dup(c);else sk_X509_push(chain,X509_dup(c));ERR_clear_error();}
        sk_X509_pop_free(all,X509_free);if(!cert)return 17;code=write_p12(argv[4],key,cert,chain);
    }else return 2;
    EVP_PKEY_free(key);X509_free(cert);sk_X509_pop_free(chain,X509_free);return code;
}
