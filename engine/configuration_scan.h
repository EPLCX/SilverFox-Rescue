// Configuration verdicts are evaluated by the signed detection engine.
namespace configuration {
std::string utf8(const std::wstring &s) {
    if(s.empty())return {};
    int n=WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
    std::string out(static_cast<size_t>(n),0);
    if(n)WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr);
    return out;
}
std::wstring wide(const std::string &s) {
    if(s.empty())return {};
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    std::wstring out(static_cast<size_t>(n),0);
    if(n)MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n);
    return out;
}
std::string text(const uint8_t *bytes,size_t n) {
    if(n>=2&&((bytes[0]==255&&bytes[1]==254)||(bytes[0]==254&&bytes[1]==255))) {
        std::wstring s;for(size_t i=2;i+1<n;i+=2)s.push_back(static_cast<wchar_t>(bytes[0]==255?bytes[i]|(uint16_t(bytes[i+1])<<8):(uint16_t(bytes[i])<<8)|bytes[i+1]));
        return utf8(s);
    }
    if(n>=3&&bytes[0]==239&&bytes[1]==187&&bytes[2]==191){bytes+=3;n-=3;}
    if(!n)return {};
    const char *raw=reinterpret_cast<const char *>(bytes);int length=static_cast<int>(n);UINT codepage=CP_UTF8;
    int chars=MultiByteToWideChar(codepage,MB_ERR_INVALID_CHARS,raw,length,nullptr,0);
    if(!chars){codepage=CP_ACP;chars=MultiByteToWideChar(codepage,0,raw,length,nullptr,0);}
    std::wstring decoded(static_cast<size_t>(chars),0);if(chars)MultiByteToWideChar(codepage,0,raw,length,decoded.data(),chars);
    return utf8(decoded);
}
bool localhost(std::string domain) {
    domain=lower(domain);while(!domain.empty()&&domain.back()=='.')domain.pop_back();
    return domain=="localhost"||(domain.size()>10&&domain.compare(domain.size()-10,10,".localhost")==0);
}
bool host_line(const std::string &line) {
    std::istringstream fields(line.substr(0,line.find('#')));std::string address,domain;
    if(!(fields>>address))return false;
    IN6_ADDR ip{};if(InetPtonA(AF_INET,address.c_str(),&ip)!=1&&InetPtonA(AF_INET6,address.c_str(),&ip)!=1)return false;
    while(fields>>domain) {
        while(!domain.empty()&&domain.back()=='.')domain.pop_back();
        if(domain.empty()||domain.size()>253||localhost(domain))continue;
        bool valid=true;size_t label=0;
        for(unsigned char ch:domain){if(ch=='.'){if(!label||label>63)valid=false;label=0;}else{if(!(ch<128&&(std::isalnum(ch)||ch=='-'||ch=='_')))valid=false;++label;}}
        if(valid&&label&&label<=63)return true;
    }
    return false;
}
void evidence(SF_Result &out,const std::string &s) {
    out.verdict=2;out.score=95;
    if(out.evidence_count<32)put_text(out.evidence[out.evidence_count++],sizeof(out.evidence[0]),s);
}
struct Reader {
    Bytes bytes;size_t at=0,work=0;
    void need(size_t n){if(n>bytes.size()-at)throw std::runtime_error("策略结构越界");}
    uint32_t u(){need(4);uint32_t v=0;std::memcpy(&v,bytes.data()+at,4);at+=4;return v;}
    uint64_t q(){uint64_t lo=u(),hi=u();return lo|(hi<<32);}
    Bytes raw(size_t n){need(n);Bytes v(bytes.begin()+at,bytes.begin()+at+n);at+=n;return v;}
    Bytes blob(){size_t n=u();auto v=raw(n);raw((4-n%4)%4);return v;}
    std::string str(){auto v=blob();if(v.size()%2||u()!=0)throw std::runtime_error("策略字符串无效");std::wstring s(v.size()/2,0);if(!v.empty())std::memcpy(s.data(),v.data(),v.size());while(!s.empty()&&s.back()==0)s.pop_back();return utf8(s);}
    size_t count(){size_t n=u();work+=n;if(n>65536||work>1000000)throw std::runtime_error("策略条目数超限");return n;}
    std::vector<uint32_t> ids(){std::vector<uint32_t> v;size_t n=count();need(n*4);for(size_t i=0;i<n;++i)v.push_back(u());return v;}
    void mark(uint32_t n){if(u()!=n)throw std::runtime_error("策略版本段无效");}
};
struct Rule {uint32_t type=0;std::string name,path,internal,description,product;uint64_t min=0,max=0;Bytes hash;};
struct Signer {uint32_t root_type=0;Bytes root;std::vector<uint32_t> eku,attrs;std::string issuer,publisher,oem;uint64_t after=0;};
struct DeniedSigner {uint32_t signer;std::vector<uint32_t> exceptions;};
struct Scenario {uint32_t value=0;std::vector<DeniedSigner> denied;std::vector<uint32_t> rules;};
struct Policy {uint32_t flags=0;std::vector<Rule> rules;std::vector<Signer> signers;std::vector<Bytes> ekus;std::vector<Scenario> scenarios;};
Bytes policy_content(const uint8_t *data,size_t n) {
    if(n>=4&&data[0]>=1&&data[0]<=7&&data[1]==0&&data[2]==0&&data[3]==0)return Bytes(data,data+n);
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(n),const_cast<BYTE *>(data)};HCERTSTORE store=nullptr;HCRYPTMSG msg=nullptr;DWORD encoding=0,type=0,format=0;
    if(!CryptQueryObject(CERT_QUERY_OBJECT_BLOB,&blob,CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,CERT_QUERY_FORMAT_FLAG_BINARY,0,&encoding,&type,&format,&store,&msg,nullptr))throw std::runtime_error("非受支持的代码完整性策略");
    char oid[128]{};DWORD oid_length=sizeof(oid);
    if(!CryptMsgGetParam(msg,CMSG_INNER_CONTENT_TYPE_PARAM,0,oid,&oid_length)||std::strcmp(oid,"1.3.6.1.4.1.311.79.1")!=0){CryptMsgClose(msg);CertCloseStore(store,0);throw std::runtime_error("非代码完整性策略签名容器");}
    DWORD len=0;bool ok=CryptMsgGetParam(msg,CMSG_CONTENT_PARAM,0,nullptr,&len)!=0;Bytes out(len);
    if(ok)ok=CryptMsgGetParam(msg,CMSG_CONTENT_PARAM,0,out.data(),&len)!=0;
    CryptMsgClose(msg);CertCloseStore(store,0);if(!ok)throw std::runtime_error("策略签名容器读取失败");
    // Some policy containers encode their content as an ASN.1 OCTET STRING.
    if(!out.empty()&&out[0]==4&&!(out.size()>=4&&out[1]==0&&out[2]==0&&out[3]==0)) {
        size_t p=2,length=out.size()>1?out[1]:0;if(out.size()<2)throw std::runtime_error("策略容器截断");
        if(length&128){size_t k=length&127;if(!k||k>4||k>out.size()-p)throw std::runtime_error("策略容器长度无效");length=0;for(size_t i=0;i<k;++i)length=(length<<8)|out[p++];}
        if(length!=out.size()-p)throw std::runtime_error("策略容器边界无效");return Bytes(out.begin()+p,out.end());
    }
    return out;
}
bool policy_header(const Bytes &bytes){
    if(bytes.size()<68)return false;uint32_t format=0,flags=0,header=0;
    std::memcpy(&format,bytes.data(),4);std::memcpy(&flags,bytes.data()+36,4);std::memcpy(&header,bytes.data()+64,4);
    return format>=1&&format<=7&&(flags&0x80000000)&&header==64;
}
Policy parse(const uint8_t *data,size_t n) {
    Reader r{policy_content(data,n)};Policy p;uint32_t format=r.u();if(format<1||format>7)throw std::runtime_error("策略格式版本不受支持");
    r.raw(32);p.flags=r.u();if(!(p.flags&0x80000000))throw std::runtime_error("策略标志无效");
    size_t e=r.count(),f=r.count(),s=r.count(),c=r.count();r.q();if(r.u()!=64)throw std::runtime_error("策略头长度无效");
    for(size_t i=0;i<e;++i)p.ekus.push_back(r.blob());
    for(size_t i=0;i<f;++i){Rule x;x.type=r.u();if(x.type>2)throw std::runtime_error("策略规则类型无效");x.name=r.str();x.min=r.q();x.hash=r.blob();p.rules.push_back(std::move(x));}
    for(size_t i=0;i<s;++i){Signer x;x.root_type=r.u();if(x.root_type>1)throw std::runtime_error("策略证书类型无效");x.root=x.root_type==0?r.blob():Bytes{static_cast<uint8_t>(r.u())};x.eku=r.ids();x.issuer=r.str();x.publisher=r.str();x.oem=r.str();x.attrs=r.ids();p.signers.push_back(std::move(x));}
    r.ids();r.ids();
    for(size_t i=0;i<c;++i){Scenario x;x.value=r.u();r.ids();r.u();for(size_t group=0;group<3;++group){size_t count=r.count();for(size_t j=0;j<count;++j){r.u();r.ids();}count=r.count();for(size_t j=0;j<count;++j){uint32_t signer=r.u();auto exceptions=r.ids();if(group==0)x.denied.push_back(DeniedSigner{signer,std::move(exceptions)});}auto rules=r.ids();if(group==0)x.rules=std::move(rules);}p.scenarios.push_back(std::move(x));}
    r.u();size_t settings=r.count();for(size_t i=0;i<settings;++i){r.str();r.str();r.str();uint32_t t=r.u();if(t<2)r.u();else if(t==2)r.blob();else if(t==3)r.str();else throw std::runtime_error("策略设置类型无效");}
    if(format>=3){r.mark(3);for(auto &x:p.rules){x.max=r.q();size_t count=r.count();for(size_t i=0;i<count;++i)r.str();}for(auto &x:p.signers)x.after=r.q();}
    if(format>=4){r.mark(4);for(auto &x:p.rules){x.internal=r.str();x.description=r.str();x.product=r.str();}}
    if(format>=5){r.mark(5);for(size_t i=0;i<f;++i){r.str();r.q();}}
    if(format>=6){r.mark(6);r.raw(32);r.ids();}
    if(format>=7){r.mark(7);for(auto &x:p.rules)x.path=r.str();}
    r.mark(format+1);if(r.at!=r.bytes.size())throw std::runtime_error("策略尾部数据无效");
    for(const auto &sc:p.scenarios){for(auto i:sc.rules)if(i>=f)throw std::runtime_error("策略文件规则引用无效");for(const auto &x:sc.denied){if(x.signer>=s)throw std::runtime_error("策略签名者引用无效");for(auto i:x.exceptions)if(i>=f||p.rules[i].type!=1)throw std::runtime_error("策略签名者例外无效");}}
    for(const auto &x:p.signers){for(auto i:x.attrs)if(i>=f)throw std::runtime_error("策略属性引用无效");for(auto i:x.eku)if(i>=e)throw std::runtime_error("策略 EKU 引用无效");}
    return p;
}
bool glob(std::string pattern,std::string value) {
    pattern=lower(pattern);value=lower(value);size_t p=0,v=0,star=std::string::npos,back=0;
    while(v<value.size()){if(p<pattern.size()&&(pattern[p]=='?'||pattern[p]==value[v])){++p;++v;}else if(p<pattern.size()&&pattern[p]=='*'){star=p++;back=v;}else if(star!=std::string::npos){p=star+1;v=++back;}else return false;}
    while(p<pattern.size()&&pattern[p]=='*')++p;return p==pattern.size();
}
const char *const security_names[]={"hipsmain.exe","hipsdaemon.exe","hipstray.exe","hrupdate.exe","360safe.exe","360tray.exe","360sd.exe","360hips.exe","360rp.exe","360rps.exe","zhudongfangyu.exe","msmpeng.exe","mpcmdrun.exe","mpdefendercoreservice.exe","nissrv.exe","qqpcrtp.exe","qqpctray.exe","usysdiag.exe","avp.exe","ekrn.exe","sentinelagent.exe","csfalconservice.exe","savservice.exe","mbamservice.exe","wrsa.exe","bdagent.exe","avastsvc.exe","mcshield.exe"};
const char *const security_dirs[]={"huorong","360\\360safe","360\\360sd","tencent\\qqpcmgr","kingsoft\\kingsoft antivirus","kaspersky","eset","sentinelone","crowdstrike","sophos","malwarebytes","avast","avg","avira","bitdefender","mcafee","norton","trend micro","cybereason","cylance","deepinstinct","doctor web","emsisoft","fireeye","palo alto","qianxin\\tianqing","tianqing","rising\\rec","sangfor","topsec\\esendpoint","windows defender"};
bool protected_name(const std::string &name){for(auto x:security_names)if(lower(name)==x)return true;return false;}
std::string environment(const char *name,const char *fallback){char out[32768];DWORD n=GetEnvironmentVariableA(name,out,sizeof(out));return n&&n<sizeof(out)?out:fallback;}
std::string expand_policy_path(std::string value){
    const std::pair<const char *,std::string> values[]={{"%osdrive%",environment("SystemDrive","C:")},{"%windir%",environment("SystemRoot","C:\\Windows")},{"%system32%",environment("SystemRoot","C:\\Windows")+"\\System32"}};
    value=lower(value);for(const auto &entry:values){size_t at=0;while((at=value.find(entry.first,at))!=std::string::npos){value.replace(at,std::strlen(entry.first),lower(entry.second));at+=entry.second.size();}}return value;
}
bool targeted_path(const std::string &path,bool directory=false) {
    auto p=lower(path);std::replace(p.begin(),p.end(),'/','\\');auto base=base_name(p);
    if(protected_name(base))return true;
    if(!directory&&base.find('*')==std::string::npos&&base.find('?')==std::string::npos&&!(base.size()>=4&&(base.compare(base.size()-4,4,".exe")==0||base.compare(base.size()-4,4,".dll")==0)))return false;
    for(auto dir:security_dirs){std::string marker="\\"+std::string(dir);auto at=p.find(marker);if(at!=std::string::npos){auto end=at+marker.size();if(end==p.size()||p[end]=='\\'||p[end]=='*')return true;}}
    return false;
}
std::vector<std::filesystem::path> installed_security_images() {
    std::vector<std::filesystem::path> out;std::error_code ec;size_t visited=0;
    std::vector<std::filesystem::path> roots={wide(environment("ProgramFiles","C:\\Program Files")),wide(environment("ProgramFiles(x86)","C:\\Program Files (x86)")),wide(environment("ProgramData","C:\\ProgramData"))+L"\\Microsoft\\Windows Defender"};
    for(const auto &root:roots){std::filesystem::directory_iterator first(root,std::filesystem::directory_options::skip_permission_denied,ec),end;for(;first!=end&&!ec;first.increment(ec)){
        auto name=lower(utf8(first->path().filename().wstring()));bool product=false;
        for(auto dir:security_dirs){std::string first_name=std::string(dir).substr(0,std::string(dir).find('\\'));if(name.compare(0,first_name.size(),first_name)==0)product=true;}
        if(!first->is_directory(ec)||(!product&&!targeted_path(utf8(root.wstring()),true)&&name!="microsoft"))continue;
        std::filesystem::recursive_directory_iterator it(first->path(),std::filesystem::directory_options::skip_permission_denied,ec),last;
        for(;it!=last&&!ec&&visited<30000;it.increment(ec)){++visited;if(it.depth()>5){it.disable_recursion_pending();continue;}if(it->is_regular_file(ec)&&protected_name(utf8(it->path().filename().wstring())))out.push_back(it->path());}
        ec.clear();
    }ec.clear();}return out;
}
std::string cert_name(PCCERT_CONTEXT cert,DWORD flags,const char *oid) {
    DWORD n=CertGetNameStringW(cert,CERT_NAME_ATTR_TYPE,flags,const_cast<char *>(oid),nullptr,0);std::wstring value(n,0);
    if(n)CertGetNameStringW(cert,CERT_NAME_ATTR_TYPE,flags,const_cast<char *>(oid),value.data(),n);while(!value.empty()&&value.back()==0)value.pop_back();return utf8(value);
}
bool tbs_matches(PCCERT_CONTEXT cert,const Bytes &hash) {
    if(hash.size()!=20&&hash.size()!=32)return false;
    CERT_SIGNED_CONTENT_INFO *decoded=nullptr;DWORD size=0;
    if(!CryptDecodeObjectEx(X509_ASN_ENCODING,X509_CERT,cert->pbCertEncoded,cert->cbCertEncoded,CRYPT_DECODE_ALLOC_FLAG,nullptr,&decoded,&size))return false;
    BYTE digest[32]{};DWORD len=static_cast<DWORD>(hash.size());bool ok=CryptHashCertificate2(hash.size()==20?L"SHA1":L"SHA256",0,nullptr,decoded->ToBeSigned.pbData,decoded->ToBeSigned.cbData,digest,&len)!=0;
    LocalFree(decoded);return ok&&len==hash.size()&&std::equal(hash.begin(),hash.end(),digest);
}
bool attributes_match(const Rule &r,const std::filesystem::path &path) {
    if(!r.hash.empty()||!r.path.empty())return false;
    DWORD unused=0,n=GetFileVersionInfoSizeW(path.c_str(),&unused);if(!n||n>1024*1024)return false;Bytes info(n);if(!GetFileVersionInfoW(path.c_str(),0,n,info.data()))return false;
    VS_FIXEDFILEINFO *fixed=nullptr;UINT size=0;if(!VerQueryValueW(info.data(),L"\\",reinterpret_cast<void **>(&fixed),&size)||size<sizeof(*fixed))return false;
    uint64_t version=(uint64_t(fixed->dwFileVersionMS)<<32)|fixed->dwFileVersionLS;
    uint64_t min=r.min==UINT64_MAX?0:r.min;if(version<min||(r.max&&version>r.max))return false;
    struct Translation {WORD language,codepage;};Translation *langs=nullptr;UINT bytes=0;if(!VerQueryValueW(info.data(),L"\\VarFileInfo\\Translation",reinterpret_cast<void **>(&langs),&bytes))return false;
    const std::pair<const char *,const std::string *> fields[]={{"OriginalFilename",&r.name},{"InternalName",&r.internal},{"FileDescription",&r.description},{"ProductName",&r.product}};
    for(UINT i=0;i<bytes/sizeof(Translation);++i){bool match=true;for(const auto &field:fields){if(field.second->empty())continue;wchar_t key[160];swprintf_s(key,L"\\StringFileInfo\\%04x%04x\\%hs",langs[i].language,langs[i].codepage,field.first);wchar_t *value=nullptr;UINT chars=0;if(!VerQueryValueW(info.data(),key,reinterpret_cast<void **>(&value),&chars)||!chars||!glob(*field.second,utf8(value))){match=false;break;}}if(match)return true;}return false;
}
bool signer_matches(const Policy &p,const Signer &s,const std::filesystem::path &path) {
    // OEM and signing-time predicates require evidence not supplied by this path.
    if(s.root_type!=0||!s.oem.empty()||s.after)return false;
    if(!s.attrs.empty()){bool match=false;for(auto i:s.attrs)if(attributes_match(p.rules[i],path)){match=true;break;}if(!match)return false;}
    WINTRUST_FILE_INFO file{};file.cbStruct=sizeof(file);file.pcwszFilePath=path.c_str();
    WINTRUST_DATA trust{};trust.cbStruct=sizeof(trust);trust.dwUIChoice=WTD_UI_NONE;trust.fdwRevocationChecks=WTD_REVOKE_NONE;trust.dwUnionChoice=WTD_CHOICE_FILE;trust.pFile=&file;trust.dwStateAction=WTD_STATEACTION_VERIFY;trust.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action=WINTRUST_ACTION_GENERIC_VERIFY_V2;LONG status=WinVerifyTrust(nullptr,&action,&trust);trust.dwStateAction=WTD_STATEACTION_CLOSE;WinVerifyTrust(nullptr,&action,&trust);if(status!=ERROR_SUCCESS)return false;
    HCERTSTORE store=nullptr;HCRYPTMSG msg=nullptr;DWORD enc=0,type=0,format=0;
    if(!CryptQueryObject(CERT_QUERY_OBJECT_FILE,path.c_str(),CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,CERT_QUERY_FORMAT_FLAG_BINARY,0,&enc,&type,&format,&store,&msg,nullptr))return false;
    DWORD n=0;bool matched=false;
    if(CryptMsgGetParam(msg,CMSG_SIGNER_CERT_INFO_PARAM,0,nullptr,&n)){Bytes info(n);if(CryptMsgGetParam(msg,CMSG_SIGNER_CERT_INFO_PARAM,0,info.data(),&n)){
        auto leaf=CertFindCertificateInStore(store,X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,0,CERT_FIND_SUBJECT_CERT,info.data(),nullptr);
        if(leaf){bool predicates=s.publisher.empty()||lower(s.publisher)==lower(cert_name(leaf,0,szOID_COMMON_NAME));predicates=predicates&&(s.issuer.empty()||lower(s.issuer)==lower(cert_name(leaf,CERT_NAME_ISSUER_FLAG,szOID_COMMON_NAME)));
            for(auto i:s.eku){const auto &eku=p.ekus[i];bool found=false;for(DWORD j=0;j<leaf->pCertInfo->cExtension;++j){const auto &ext=leaf->pCertInfo->rgExtension[j];if(std::strcmp(ext.pszObjId,szOID_ENHANCED_KEY_USAGE)==0&&eku.size()>2&&std::search(ext.Value.pbData,ext.Value.pbData+ext.Value.cbData,eku.begin()+2,eku.end())!=ext.Value.pbData+ext.Value.cbData)found=true;}if(!found)predicates=false;}
            CERT_CHAIN_PARA para{};para.cbSize=sizeof(para);PCCERT_CHAIN_CONTEXT chain=nullptr;
            if(predicates&&CertGetCertificateChain(nullptr,leaf,nullptr,store,&para,CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,nullptr,&chain)){for(DWORD i=0;i<chain->cChain;++i)for(DWORD j=0;j<chain->rgpChain[i]->cElement;++j)if(tbs_matches(chain->rgpChain[i]->rgpElement[j]->pCertContext,s.root))matched=true;CertFreeCertificateChain(chain);}CertFreeCertificateContext(leaf);
        }
    }}CryptMsgClose(msg);CertCloseStore(store,0);return matched;
}
}
extern "C" __declspec(dllexport) int __cdecl sf_hosts_line(const char *line){return line&&configuration::host_line(line)?1:0;}
extern "C" __declspec(dllexport) int __cdecl sf_hosts_localhost(const char *domain){return domain&&configuration::localhost(domain)?1:0;}
extern "C" __declspec(dllexport) int __cdecl sf_is_ci_policy(const uint8_t *bytes,size_t n){
    if(!bytes||n>16*1024*1024)return 0;
    try{return configuration::policy_header(configuration::policy_content(bytes,n))?1:0;}catch(const std::exception &){return 0;}
}
extern "C" __declspec(dllexport) int __cdecl sf_scan_hosts(const uint8_t *bytes,size_t n,SF_Result *out) {
    if(!out||(!bytes&&n)||n>16*1024*1024)return 0;std::memset(out,0,sizeof(*out));
    std::istringstream lines(configuration::text(bytes,n));std::string line;size_t index=0;
    while(std::getline(lines,line)){++index;if(configuration::host_line(line))configuration::evidence(*out,"hosts 第 "+std::to_string(index)+" 行存在非 localhost 域名映射："+line);}
    if(out->verdict)out->score=90;return 1;
}
extern "C" __declspec(dllexport) int __cdecl sf_scan_ci_policy(const uint8_t *bytes,size_t n,SF_Result *out) {
    if(!out||!bytes||n>16*1024*1024)return 0;std::memset(out,0,sizeof(*out));
    try {
        auto p=configuration::parse(bytes,n);if(!(p.flags&4)||(p.flags&0x10000))return 1;
        std::vector<std::filesystem::path> images;bool inventory=false;
        for(const auto &sc:p.scenarios){if(sc.value!=12)continue;
            for(auto i:sc.rules){const auto &r=p.rules[i];if(r.type!=0||!r.hash.empty())continue;
                if(!r.path.empty()&&configuration::targeted_path(r.path))configuration::evidence(*out,"AppControl.SecurityBlock：用户模式强制拒绝规则 "+std::to_string(i)+"，路径："+r.path);
                else if(r.path.empty()&&(!r.name.empty()||!r.internal.empty()||!r.description.empty()||!r.product.empty())){if(!inventory){images=configuration::installed_security_images();inventory=true;}for(const auto &image:images)if(configuration::attributes_match(r,image)){configuration::evidence(*out,"AppControl.SecurityBlock：拒绝文件身份规则 "+std::to_string(i)+" 匹配 "+configuration::utf8(image.wstring()));break;}}
            }
            if(!sc.denied.empty()){
                if(!inventory){images=configuration::installed_security_images();inventory=true;}
                for(const auto &denied:sc.denied)for(const auto &image:images)if(configuration::signer_matches(p,p.signers[denied.signer],image)){
                    bool exempt=false;for(auto i:denied.exceptions){const auto &allow=p.rules[i];if(!allow.hash.empty()){exempt=true;break;}if(allow.path.empty()?configuration::attributes_match(allow,image):configuration::glob(configuration::expand_policy_path(allow.path),configuration::utf8(image.wstring()))){exempt=true;break;}}
                    if(!exempt){configuration::evidence(*out,"AppControl.SecurityBlock：拒绝签名者规则 "+std::to_string(denied.signer)+" 匹配证书及文件条件："+configuration::utf8(image.wstring()));break;}
                }
            }
        }return 1;
    }catch(const std::exception &error){out->verdict=3;put_text(out->evidence[0],sizeof(out->evidence[0]),error.what());out->evidence_count=1;return 1;}
}
