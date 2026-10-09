// SilverFox updateable detection engine. This translation unit is compiled to
// algorithms.dll and is distributed ONLY inside a signed rule package.
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <stdexcept>
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include "ml_model.generated.h"

// Project-owned Ed25519 signature slot; unrelated to Authenticode. The build
// tool fills it after linking, and the host verifies it before LoadLibrary.
#pragma section(".sfsig", read)
#pragma comment(linker, "/include:sf_engine_signature_slot")
extern "C" __declspec(allocate(".sfsig")) const unsigned char sf_engine_signature_slot[128] = {
    'S', 'F', 'X', 'S', 'I', 'G', '0', '1', 1
};

extern "C" {
struct SF_FileInput {
    uint32_t abi;
    const char *path;
    const uint8_t *sample;
    size_t sample_len;
    uint64_t total_len;
    uint32_t signature_state; // 0 none, 1 valid, 2 tampered, 3 revoked, 4 not trusted, 5 untrusted, 6 expired
    uint8_t embedded_certificate;
    const char *const *siblings;
    size_t sibling_count;
    uint64_t gpu_prefilter_hits;
    uint64_t gpu_prefilter_valid;
    const uint32_t *gpu_ml_histogram;
    size_t gpu_ml_histogram_len;
};
struct SF_Result {
    uint32_t verdict; // 0 clean, 1 suspicious, 2 malicious
    uint16_t score;
    uint16_t evidence_count;
    char evidence[32][768];
};
struct SF_ServiceInput {
    float cpu_share_percent;
    uint32_t sample_seconds;
    size_t hosted_service_count;
    size_t unbacked_modules;
    size_t unbacked_services;
    size_t untrusted_service_images;
    size_t orphaned_services;
    uint8_t duty_mismatch;
};
struct SF_ServiceResult {
    SF_Result finding;
    uint16_t cleanup_count;
    char cleanup[12][768];
};
__declspec(dllexport) uint32_t __cdecl sf_engine_abi();
__declspec(dllexport) int __cdecl sf_scan_file(const SF_FileInput *, SF_Result *);
__declspec(dllexport) int __cdecl sf_assess_service_host(const SF_ServiceInput *, SF_ServiceResult *);
__declspec(dllexport) int __cdecl sf_random_process_name(const char *);
__declspec(dllexport) int __cdecl sf_dual_use_remote_process(const char *);
__declspec(dllexport) int __cdecl sf_sideloaded_module(const char *, const char *, int, int, int, SF_Result *);
__declspec(dllexport) int __cdecl sf_is_windows_path(const char *);
__declspec(dllexport) int __cdecl sf_is_user_writable_path(const char *);
__declspec(dllexport) int __cdecl sf_directory_hidden_system(const char *);
__declspec(dllexport) int __cdecl sf_signature_untrusted(const char *);
__declspec(dllexport) int __cdecl sf_hosted_duty_idle(const char *const *,size_t,const char *const *,size_t,int,int);
}

namespace {
using Bytes = std::vector<uint8_t>;
using Span = std::pair<const uint8_t *, size_t>;
enum class Category { Family, Capability, Execution, Persistence, Injection, SideLoad, Miner, Integrity, Masquerade, Packing, Entropy, Location };
enum class Strength { Context=1, Corroborating=2, Strong=3 };
struct Signal { std::string id; Category category; Strength strength; unsigned score; std::string detail; };
struct Section { std::string name; size_t offset; size_t size; bool executable; uint32_t va; uint32_t virtual_size; };
struct Pe { size_t pe; size_t optional_size; uint16_t magic; std::vector<Section> sections; uint64_t raw_end; };

std::string lower(std::string value) {
    for (char &c : value) c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}
std::string base_name(const std::string &path) {
    auto at=path.find_last_of("\\/"); return at==std::string::npos?path:path.substr(at+1);
}
bool starts(Span data, const char *needle, size_t length) {
    return data.second>=length && std::memcmp(data.first,needle,length)==0;
}
bool contains(Span data, const std::string &needle) {
    if (needle.empty() || data.second<needle.size()) return false;
    for (size_t i=0;i+needle.size()<=data.second;++i) {
        size_t j=0;
        for (;j<needle.size();++j) if (std::tolower(data.first[i+j])!=std::tolower(static_cast<unsigned char>(needle[j]))) break;
        if (j==needle.size()) return true;
    }
    return false;
}
bool contains_text(const std::string &haystack,const std::string &needle) {
    return lower(haystack).find(lower(needle))!=std::string::npos;
}
std::string environment(const char *name) {
    char *value=nullptr;size_t size=0;
    if (_dupenv_s(&value,&size,name)!=0 || !value) return {};
    auto result=lower(value);std::free(value);return result;
}
bool path_prefix(const std::string &path,std::string root) {
    if (root.empty()) return false;
    while (!root.empty() && (root.back()=='\\'||root.back()=='/')) root.pop_back();
    root.push_back('\\');
    return path.compare(0,root.size(),root)==0;
}
bool windows_path(const std::string &path) {
    auto root=environment("WINDIR");if (root.empty()) root="c:\\windows\\";
    return lower(path).compare(0,root.size(),root)==0;
}
bool user_writable_path(const std::string &path) {
    auto value=lower(path);
    for (auto name:{"PROGRAMDATA","PUBLIC","APPDATA","LOCALAPPDATA","TEMP"})
        if (path_prefix(value,environment(name))) return true;
    auto profile=environment("USERPROFILE");
    if (path_prefix(value,profile+"\\documents")) return true;
    auto drive=environment("SystemDrive");if (drive.empty()) drive="c:";
    return path_prefix(value,drive+"\\inetpub")||path_prefix(value,drive+"\\windows\\temp");
}
bool concealed_directory(const std::string &path) {
    auto parent=std::filesystem::u8path(path).parent_path();
    DWORD flags=GetFileAttributesW(parent.c_str());
    return flags!=INVALID_FILE_ATTRIBUTES && (flags&FILE_ATTRIBUTE_HIDDEN) && (flags&FILE_ATTRIBUTE_SYSTEM);
}
uint16_t read16(Span data,size_t at) {
    if (at>data.second || data.second-at<2) return 0;
    return uint16_t(data.first[at]) | (uint16_t(data.first[at+1])<<8);
}
uint32_t read32(Span data,size_t at) {
    if (at>data.second || data.second-at<4) return 0;
    return uint32_t(data.first[at]) | (uint32_t(data.first[at+1])<<8) |
        (uint32_t(data.first[at+2])<<16) | (uint32_t(data.first[at+3])<<24);
}
uint32_t read_be32(Span data,size_t at) {
    if (at>data.second || data.second-at<4) return 0;
    return (uint32_t(data.first[at])<<24) | (uint32_t(data.first[at+1])<<16) |
        (uint32_t(data.first[at+2])<<8) | uint32_t(data.first[at+3]);
}
Span subspan(Span data,size_t start,size_t len) {
    if (start>=data.second) return {data.first+data.second,0};
    return {data.first+start,std::min(len,data.second-start)};
}
double entropy(Span data) {
    if (!data.second) return 0;
    std::array<size_t,256> counts{};
    for (size_t i=0;i<data.second;++i) ++counts[data.first[i]];
    double result=0;
    for (auto count:counts) if (count) { double p=double(count)/double(data.second); result-=p*std::log2(p); }
    return result;
}
bool parse_pe(Span data,Pe &out) {
    if (!starts(data,"MZ",2) || data.second<64) return false;
    size_t pe=read32(data,0x3c);
    if (pe>data.second || data.second-pe<24 || std::memcmp(data.first+pe,"PE\0\0",4)!=0) return false;
    uint16_t count=read16(data,pe+6); size_t optional=read16(data,pe+20);
    if (optional>data.second-pe-24) return false;
    out.pe=pe;out.optional_size=optional;out.magic=read16(data,pe+24);out.raw_end=0;out.sections.clear();
    size_t table=pe+24+optional;
    for (size_t i=0;i<std::min<size_t>(count,64) && table<=data.second && data.second-table>=40;++i,table+=40) {
        std::string name(reinterpret_cast<const char *>(data.first+table),8);
        auto terminator=name.find('\0');if (terminator!=std::string::npos) name.resize(terminator);
        auto offset=read32(data,table+20),size=read32(data,table+16);
        out.raw_end=std::max<uint64_t>(out.raw_end,uint64_t(offset)+size);
        out.sections.push_back({name,offset,size,bool(read32(data,table+36)&0x20000000),read32(data,table+12),std::max(read32(data,table+8),read32(data,table+16))});
    }
    return true;
}
// Keep this extractor shared by training and inference: the Python trainer calls
// sf_extract_pe_metadata from the compiled engine, so offsets cannot drift.
struct OverlayInfo { uint64_t start, size; size_t certificate=0, certificate_size=0; };
OverlayInfo pe_overlay(Span data,uint64_t total_len,const Pe &pe) {
    OverlayInfo out{pe.raw_end,total_len>pe.raw_end?total_len-pe.raw_end:0};
    const size_t optional=pe.pe+24, relative=pe.magic==0x20b?112:96;
    if((pe.magic!=0x10b && pe.magic!=0x20b)||pe.optional_size<relative+40||read32(data,optional+relative-4)<5)return out;
    const size_t cert=read32(data,optional+relative+32),size=read32(data,optional+relative+36);
    if(!size||cert%8||cert<pe.raw_end||cert>data.second||size>data.second-cert||uint64_t(cert)+size>total_len)return out;
    // Validate all WIN_CERTIFICATE records; invalid directory pointers remain overlay.
    const size_t end=cert+size;
    for(size_t at=cert;at<end;) {
        if(end-at<8)return out;
        const size_t length=read32(data,at);
        if(length<10||length>end-at||read16(data,at+4)!=0x200||read16(data,at+6)!=2||data.first[at+8]!=0x30)return out;
        size_t header=2,body=data.first[at+9];
        if(body&0x80) {
            const size_t count=body&0x7f;
            if(!count||count>4||length<10+count)return out;
            header+=count;body=0;
            for(size_t i=0;i<count;++i)body=(body<<8)|data.first[at+10+i];
        }
        const uint8_t signed_data_oid[]={0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02};
        if(header+body>length-8||body<sizeof(signed_data_oid)||std::memcmp(data.first+at+8+header,signed_data_oid,sizeof(signed_data_oid))!=0)return out;
        for(size_t i=at+8+header+body;i<at+length;++i)if(data.first[i])return out;
        const size_t aligned=(length+7)&~size_t(7);
        if(aligned>end-at)return out;
        for(size_t i=at+length;i<at+aligned;++i)if(data.first[i])return out;
        at+=aligned;
    }
    out.certificate=cert;out.certificate_size=size;out.size-=size;return out;
}
std::vector<uint8_t> overlay_sample(Span data,const OverlayInfo &info) {
    std::vector<uint8_t> bytes;
    const size_t start=static_cast<size_t>(std::min<uint64_t>(info.start,data.second));
    const auto append=[&](size_t begin,size_t end) {
        const size_t length=std::min<size_t>(end-begin,1048576-bytes.size());
        bytes.insert(bytes.end(),data.first+begin,data.first+begin+length);
    };
    if(info.certificate_size){append(start,info.certificate);append(info.certificate+info.certificate_size,data.second);}
    else append(start,data.second);
    return bytes;
}
constexpr size_t PE_METADATA_COUNT=71;
constexpr std::array<size_t,15> EXCLUDED_MODEL_METADATA={23,30,33,34,35,47,52,63,64,65,66,67,68,69,70};
constexpr size_t MODEL_METADATA_COUNT=PE_METADATA_COUNT-EXCLUDED_MODEL_METADATA.size();
void pe_metadata(Span data,uint64_t total_len,const Pe &pe,double *v) {
    std::fill(v,v+PE_METADATA_COUNT,0.0);
    const size_t o=pe.pe+24, coff=pe.pe+4;
    const auto rd=[&](size_t at)->uint32_t{return read32(data,at);};
    const auto word=[&](size_t at)->uint16_t{return read16(data,at);};
    const uint32_t stamp=rd(coff+4), flags=word(coff+18);
    v[0]=double(stamp);v[1]=(stamp==0||stamp==0xffffffffu);v[2]=word(coff);
    v[3]=flags;v[4]=bool(flags&0x2000);v[5]=bool(flags&0x20);v[6]=bool(flags&0x1000);
    v[7]=pe.magic;v[8]=word(o+68);v[9]=word(o+70);v[10]=rd(o+16);v[11]=rd(o+56);
    const uint32_t stored_checksum=rd(o+64);v[12]=stored_checksum!=0;
    if(data.second==total_len && total_len<=UINT32_MAX) {
        uint64_t sum=0;const size_t checksum_at=o+64;
        for(size_t i=0;i+1<data.second;i+=2) {
            if(i==checksum_at||i==checksum_at+2) continue;
            sum+=uint16_t(data.first[i]|(uint16_t(data.first[i+1])<<8));sum=(sum&0xffff)+(sum>>16);
        }
        if(data.second&1) sum+=data.first[data.second-1];
        sum=(sum&0xffff)+(sum>>16);sum=(sum&0xffff)+(sum>>16);
        v[13]=(stored_checksum!=0 && uint32_t(sum+data.second)==stored_checksum);
        v[58]=(stored_checksum!=0 && !v[13]);
    }
    auto map=[&](uint32_t rva)->size_t {
        for(const auto &s:pe.sections) if(rva>=s.va && uint64_t(rva)<uint64_t(s.va)+s.virtual_size) {
            const size_t at=s.offset+size_t(rva-s.va);return at<data.second?at:SIZE_MAX;
        }
        return SIZE_MAX;
    };
    const size_t dirs=o+(pe.magic==0x20b?112:96);
    auto directory=[&](size_t n)->uint32_t {return dirs+8*n+8<=o+pe.optional_size?rd(dirs+8*n):0;};
    const std::set<std::string> defaults={".text",".data",".rdata",".rsrc",".reloc",".bss",".idata",".edata",".tls",".pdata",".xdata",".debug"};
    for(const auto &s:pe.sections) {
        size_t table=pe.pe+24+pe.optional_size+(&s-&pe.sections[0])*40;
        uint32_t attr=rd(table+36);bool x=attr&0x20000000,r=attr&0x40000000,w=attr&0x80000000;
        v[14]+=x&&w;v[15]+=r&&w&&x;v[16]+=w;v[17]+=!defaults.count(lower(s.name));
        v[18]+=s.name.empty();v[19]+=s.size==0;v[20]=std::max(v[20],double(s.size));
        if(s.offset<data.second && s.size) {auto block=subspan(data,s.offset,std::min<size_t>(s.size,262144));if(entropy(block)>7.2)v[21]++;}
        if(rd(o+16)>=s.va && uint64_t(rd(o+16))<uint64_t(s.va)+s.virtual_size && x)v[59]=1;
    }
    if(!pe.sections.empty())v[22]=v[17]/pe.sections.size();
    for(size_t a=0;a<pe.sections.size();++a)for(size_t b=a+1;b<pe.sections.size();++b){
        const auto &left=pe.sections[a],&right=pe.sections[b];
        if(left.size && right.size && left.offset<uint64_t(right.offset)+right.size && right.offset<uint64_t(left.offset)+left.size)v[60]++;
    }
    v[61]=pe.sections.empty()?0:v[15]/pe.sections.size();
    const uint32_t import_rva=directory(1);size_t descriptor=map(import_rva);
    std::set<std::string> dlls;
    for(size_t i=0;import_rva && i<512 && descriptor<data.second && data.second-descriptor>=20;i++,descriptor+=20) {
        uint32_t name_rva=rd(descriptor+12), thunk_rva=rd(descriptor);
        if(!name_rva && !thunk_rva && !rd(descriptor+16))break;
        v[56]++;
        size_t at=map(name_rva);if(at==SIZE_MAX)continue;
        size_t end=at;while(end<data.second && end-at<260 && data.first[end])end++;
        std::string dll=lower(std::string(reinterpret_cast<const char*>(data.first+at),end-at));dlls.insert(dll);
        if(dll.find("advapi32")!=std::string::npos)v[24]++;
        if(dll.find("crypt")!=std::string::npos||dll.find("bcrypt")!=std::string::npos)v[25]++;
        size_t thunk=map(thunk_rva?thunk_rva:rd(descriptor+16));size_t step=pe.magic==0x20b?8:4;
        for(size_t j=0;j<1024 && thunk<data.second && data.second-thunk>=step;j++,thunk+=step) {
            uint64_t value=rd(thunk);if(step==8)value|=uint64_t(rd(thunk+4))<<32;if(!value)break;v[26]++;
            if(value&(step==8?(uint64_t(1)<<63):0x80000000u)) {v[27]++;continue;}
            size_t name=map(uint32_t(value));if(name==SIZE_MAX||name+2>=data.second)continue;
            size_t finish=name+2;while(finish<data.second && finish-name<256 && data.first[finish])finish++;
            std::string api=lower(std::string(reinterpret_cast<const char*>(data.first+name+2),finish-name-2));
            if(api.find("virtualalloc")!=std::string::npos||api.find("writeprocessmemory")!=std::string::npos||api.find("createremotethread")!=std::string::npos)v[28]++;
            if(api.find("regsetvalue")!=std::string::npos||api.find("createservice")!=std::string::npos||api.find("schtasks")!=std::string::npos)v[29]++;
            if(api.find("crypt")!=std::string::npos||api.find("bcrypt")!=std::string::npos)v[31]++;
        }
    }
    v[32]=static_cast<double>(dlls.size());
    v[62]=v[26]/std::max<double>(v[32],1.0);
    size_t export_at=map(directory(0));
    if(export_at!=SIZE_MAX && data.second-export_at>=40) {
        uint32_t functions=std::min<uint32_t>(rd(export_at+20),65536),address_rva=rd(export_at+28);
        v[36]=functions;uint32_t export_rva=directory(0),export_size=dirs+8<=o+pe.optional_size?rd(dirs+4):0;
        size_t address_at=map(address_rva);
        for(uint32_t i=0;i<functions && address_at<data.second && data.second-address_at>=4;i++,address_at+=4) {
            uint32_t target=rd(address_at);if(target>=export_rva && uint64_t(target)<uint64_t(export_rva)+export_size)v[37]++;
        }
        v[57]=v[37]/std::max<double>(v[36],1.0);
    }
    size_t resource_at=map(directory(2));v[38]=resource_at!=SIZE_MAX;
    if(resource_at!=SIZE_MAX && data.second-resource_at>=16) {
        size_t entries=std::min<size_t>(word(resource_at+12)+word(resource_at+14),256);v[39]=static_cast<double>(entries);
        for(size_t i=0;i<entries && resource_at+16+i*8+8<=data.second;i++) {
            uint32_t id=rd(resource_at+16+i*8);if(!(id&0x80000000u)) {v[40]+=id==16;v[41]+=id==24;v[42]+=id==6;}
        }
    }
    const auto overlay=pe_overlay(data,total_len,pe);v[43]=std::log1p(double(overlay.size));
    const auto tail=overlay_sample(data,overlay);
    if(!tail.empty()) {Span ov{tail.data(),tail.size()};v[44]=entropy(ov);size_t printable=0;for(size_t i=0;i<ov.second;i++)printable+=ov.first[i]>=32&&ov.first[i]<=126;v[45]=double(printable)/ov.second;v[46]=starts(ov,"MZ",2)||starts(ov,"PK",2);}
    // ASCII/UTF-16LE strings, bounded to the same sample window as inference.
    for(size_t i=0;i<data.second;) {
        bool wide=i+1<data.second && data.first[i]>=32 && data.first[i]<=126 && data.first[i+1]==0;
        size_t step=wide?2:1,j=i;std::string token;
        while(j+step<=data.second && token.size()<512 && data.first[j]>=32 && data.first[j]<=126 && (!wide||data.first[j+1]==0)) {token.push_back(char(std::tolower(data.first[j])));j+=step;}
        if(token.size()>=8) {
            bool path=token.find("\\appdata\\")!=std::string::npos||token.find("c:\\users\\")!=std::string::npos||token.find("\\windows\\")!=std::string::npos;
            bool command=token.find("powershell")!=std::string::npos||token.find("cmd.exe")!=std::string::npos||token.find("rundll32")!=std::string::npos||token.find("schtasks")!=std::string::npos;
            v[48]+=token.find("companyname")!=std::string::npos;
            v[49]+=token.find("productname")!=std::string::npos;v[50]+=token.find("originalfilename")!=std::string::npos;
            v[51]+=token.find("filedescription")!=std::string::npos;v[53]+=path;v[54]+=command;
            v[55]+=token.find(".exe")!=std::string::npos&&token.find("\\")!=std::string::npos;
            i=j;
        }else i++;
    }
}
// V2 offsets mirror FEATURE_NAMES in tools/train_lightgbm.py.
namespace silverfox_features {
constexpr size_t COUNT=657;
constexpr size_t LEGACY_INDICES[]={256,257,258,259,260,261,262,263,264,265,266,267,268,269,270,272,273,275,276,277,278,279,283,284,285,286,287,288,289,290,291,292,293,294,295,296,297,298,299,300,301,302,303,304,305,306,307,308,309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,325,326};
constexpr size_t F_api_anti_debug_checkremotedebuggerpresent=170;
constexpr size_t F_api_anti_debug_isdebuggerpresent=169;
constexpr size_t F_api_anti_debug_ntqueryinformationprocess=171;
constexpr size_t F_api_anti_debug_outputdebugstringa=172;
constexpr size_t F_api_anti_debug_outputdebugstringw=173;
constexpr size_t F_api_crypto_bcryptdecrypt=205;
constexpr size_t F_api_crypto_bcryptencrypt=204;
constexpr size_t F_api_crypto_cryptacquirecontexta=202;
constexpr size_t F_api_crypto_cryptacquirecontextw=203;
constexpr size_t F_api_crypto_cryptdecrypt=201;
constexpr size_t F_api_crypto_cryptencrypt=200;
constexpr size_t F_api_injection_createremotethread=160;
constexpr size_t F_api_injection_ntcreatethreadex=161;
constexpr size_t F_api_injection_queueuserapc=162;
constexpr size_t F_api_injection_setthreadcontext=163;
constexpr size_t F_api_injection_virtualallocex=158;
constexpr size_t F_api_injection_writeprocessmemory=159;
constexpr size_t F_api_keyboard_getasynckeystate=166;
constexpr size_t F_api_keyboard_getkeystate=167;
constexpr size_t F_api_keyboard_getrawinputdata=168;
constexpr size_t F_api_keyboard_setwindowshookexa=164;
constexpr size_t F_api_keyboard_setwindowshookexw=165;
constexpr size_t F_api_network_connect=184;
constexpr size_t F_api_network_internetconnecta=176;
constexpr size_t F_api_network_internetconnectw=177;
constexpr size_t F_api_network_internetopena=174;
constexpr size_t F_api_network_internetopenw=175;
constexpr size_t F_api_network_internetreadfile=178;
constexpr size_t F_api_network_recv=186;
constexpr size_t F_api_network_send=185;
constexpr size_t F_api_network_urldownloadtofilea=179;
constexpr size_t F_api_network_urldownloadtofilew=180;
constexpr size_t F_api_network_winhttpconnect=182;
constexpr size_t F_api_network_winhttpopen=181;
constexpr size_t F_api_network_winhttpsendrequest=183;
constexpr size_t F_api_registry_regcreatekeyexa=194;
constexpr size_t F_api_registry_regcreatekeyexw=195;
constexpr size_t F_api_registry_regdeletevaluea=198;
constexpr size_t F_api_registry_regdeletevaluew=199;
constexpr size_t F_api_registry_regsetvalueexa=196;
constexpr size_t F_api_registry_regsetvalueexw=197;
constexpr size_t F_api_service_controlservice=193;
constexpr size_t F_api_service_createservicea=189;
constexpr size_t F_api_service_createservicew=190;
constexpr size_t F_api_service_openscmanagera=187;
constexpr size_t F_api_service_openscmanagerw=188;
constexpr size_t F_api_service_startservicea=191;
constexpr size_t F_api_service_startservicew=192;
constexpr size_t F_bound_import_count=156;
constexpr size_t F_byte_entropy_00_00=401;
constexpr size_t F_chunk_count=99;
constexpr size_t F_chunk_entropy_p10=100;
constexpr size_t F_chunk_entropy_p50=101;
constexpr size_t F_chunk_entropy_p90=102;
constexpr size_t F_code_size_ratio=131;
constexpr size_t F_coff_flag_relocs_stripped=214;
constexpr size_t F_debug_directory_present=137;
constexpr size_t F_delay_import_count=155;
constexpr size_t F_dll_flag_high_entropy_va=206;
constexpr size_t F_e_language_eapi_string=123;
constexpr size_t F_e_language_krnln_import=122;
constexpr size_t F_embedded_pe_count=115;
constexpr size_t F_entry_pre256_entropy=149;
constexpr size_t F_entry_rva_image_ratio=150;
constexpr size_t F_entry_section_entropy=141;
constexpr size_t F_entry_section_is_last=142;
constexpr size_t F_entry_section_name_standard=143;
constexpr size_t F_entry_section_relative_offset=152;
constexpr size_t F_headers_size_anomalous=134;
constexpr size_t F_image_file_ratio=151;
constexpr size_t F_import_api_hash_000=241;
constexpr size_t F_import_dll_hash_00=369;
constexpr size_t F_import_minimal_flag=154;
constexpr size_t F_import_ordinal_ratio=157;
constexpr size_t F_initialized_data_size_ratio=132;
constexpr size_t F_linker_major=125;
constexpr size_t F_linker_minor=126;
constexpr size_t F_load_config_present=140;
constexpr size_t F_max_byte_ratio=82;
constexpr size_t F_max_byte_value=83;
constexpr size_t F_nz_chunk_entropy_max=95;
constexpr size_t F_nz_chunk_entropy_mean=92;
constexpr size_t F_nz_chunk_entropy_min=94;
constexpr size_t F_nz_chunk_entropy_std=93;
constexpr size_t F_nz_count_log1p=85;
constexpr size_t F_nz_entropy=91;
constexpr size_t F_nz_high_bit_ratio=97;
constexpr size_t F_nz_printable_ratio=96;
constexpr size_t F_nz_unique_byte_ratio=98;
constexpr size_t F_os_major=127;
constexpr size_t F_os_minor=128;
constexpr size_t F_overlay_embedded_pe_count=113;
constexpr size_t F_overlay_magic_7z=109;
constexpr size_t F_overlay_magic_inno=112;
constexpr size_t F_overlay_magic_nsis=111;
constexpr size_t F_overlay_magic_rar=110;
constexpr size_t F_overlay_magic_zip=108;
constexpr size_t F_packer_aspack=121;
constexpr size_t F_packer_mpress=120;
constexpr size_t F_packer_themida=119;
constexpr size_t F_packer_upx_magic=117;
constexpr size_t F_packer_upx_section=116;
constexpr size_t F_packer_vmprotect_section=118;
constexpr size_t F_pdb_path_present=138;
constexpr size_t F_relocations_present=139;
constexpr size_t F_resource_embedded_pe_count=114;
constexpr size_t F_resource_embedded_pe_header=105;
constexpr size_t F_resource_icon_count=106;
constexpr size_t F_resource_language_id_count=107;
constexpr size_t F_resource_max_entropy=104;
constexpr size_t F_resource_total_size_ratio=103;
constexpr size_t F_rich_hash_00=225;
constexpr size_t F_rich_header_present=124;
constexpr size_t F_section_entropy_max=146;
constexpr size_t F_section_entropy_min=147;
constexpr size_t F_section_entropy_weighted_mean=148;
constexpr size_t F_section_raw_virtual_ratio_max=144;
constexpr size_t F_section_raw_virtual_ratio_min=145;
constexpr size_t F_subsystem_major=129;
constexpr size_t F_subsystem_minor=130;
constexpr size_t F_timestamp_before_1995=153;
constexpr size_t F_tls_callback_count=136;
constexpr size_t F_tls_present=135;
constexpr size_t F_top_run_byte_ratio=84;
constexpr size_t F_uninitialized_data_size_ratio=133;
constexpr size_t F_zero_chunk_ratio=88;
constexpr size_t F_zero_in_long_runs_ratio=87;
constexpr size_t F_zero_ratio_overlay=89;
constexpr size_t F_zero_ratio_sections=90;
constexpr size_t F_zero_run_max_ratio=86;
}
// Extended static features share the layout defined in tools/train_lightgbm.py.
namespace extended_ml {
using namespace silverfox_features;
void apply_api_flags(const std::set<std::string> &apis,double *out) {
    out[F_api_injection_virtualallocex]=apis.count("virtualallocex")!=0;
    out[F_api_injection_writeprocessmemory]=apis.count("writeprocessmemory")!=0;
    out[F_api_injection_createremotethread]=apis.count("createremotethread")!=0;
    out[F_api_injection_ntcreatethreadex]=apis.count("ntcreatethreadex")!=0;
    out[F_api_injection_queueuserapc]=apis.count("queueuserapc")!=0;
    out[F_api_injection_setthreadcontext]=apis.count("setthreadcontext")!=0;
    out[F_api_keyboard_setwindowshookexa]=apis.count("setwindowshookexa")!=0;
    out[F_api_keyboard_setwindowshookexw]=apis.count("setwindowshookexw")!=0;
    out[F_api_keyboard_getasynckeystate]=apis.count("getasynckeystate")!=0;
    out[F_api_keyboard_getkeystate]=apis.count("getkeystate")!=0;
    out[F_api_keyboard_getrawinputdata]=apis.count("getrawinputdata")!=0;
    out[F_api_anti_debug_isdebuggerpresent]=apis.count("isdebuggerpresent")!=0;
    out[F_api_anti_debug_checkremotedebuggerpresent]=apis.count("checkremotedebuggerpresent")!=0;
    out[F_api_anti_debug_ntqueryinformationprocess]=apis.count("ntqueryinformationprocess")!=0;
    out[F_api_anti_debug_outputdebugstringa]=apis.count("outputdebugstringa")!=0;
    out[F_api_anti_debug_outputdebugstringw]=apis.count("outputdebugstringw")!=0;
    out[F_api_network_internetopena]=apis.count("internetopena")!=0;
    out[F_api_network_internetopenw]=apis.count("internetopenw")!=0;
    out[F_api_network_internetconnecta]=apis.count("internetconnecta")!=0;
    out[F_api_network_internetconnectw]=apis.count("internetconnectw")!=0;
    out[F_api_network_internetreadfile]=apis.count("internetreadfile")!=0;
    out[F_api_network_urldownloadtofilea]=apis.count("urldownloadtofilea")!=0;
    out[F_api_network_urldownloadtofilew]=apis.count("urldownloadtofilew")!=0;
    out[F_api_network_winhttpopen]=apis.count("winhttpopen")!=0;
    out[F_api_network_winhttpconnect]=apis.count("winhttpconnect")!=0;
    out[F_api_network_winhttpsendrequest]=apis.count("winhttpsendrequest")!=0;
    out[F_api_network_connect]=apis.count("connect")!=0;
    out[F_api_network_send]=apis.count("send")!=0;
    out[F_api_network_recv]=apis.count("recv")!=0;
    out[F_api_service_openscmanagera]=apis.count("openscmanagera")!=0;
    out[F_api_service_openscmanagerw]=apis.count("openscmanagerw")!=0;
    out[F_api_service_createservicea]=apis.count("createservicea")!=0;
    out[F_api_service_createservicew]=apis.count("createservicew")!=0;
    out[F_api_service_startservicea]=apis.count("startservicea")!=0;
    out[F_api_service_startservicew]=apis.count("startservicew")!=0;
    out[F_api_service_controlservice]=apis.count("controlservice")!=0;
    out[F_api_registry_regcreatekeyexa]=apis.count("regcreatekeyexa")!=0;
    out[F_api_registry_regcreatekeyexw]=apis.count("regcreatekeyexw")!=0;
    out[F_api_registry_regsetvalueexa]=apis.count("regsetvalueexa")!=0;
    out[F_api_registry_regsetvalueexw]=apis.count("regsetvalueexw")!=0;
    out[F_api_registry_regdeletevaluea]=apis.count("regdeletevaluea")!=0;
    out[F_api_registry_regdeletevaluew]=apis.count("regdeletevaluew")!=0;
    out[F_api_crypto_cryptencrypt]=apis.count("cryptencrypt")!=0;
    out[F_api_crypto_cryptdecrypt]=apis.count("cryptdecrypt")!=0;
    out[F_api_crypto_cryptacquirecontexta]=apis.count("cryptacquirecontexta")!=0;
    out[F_api_crypto_cryptacquirecontextw]=apis.count("cryptacquirecontextw")!=0;
    out[F_api_crypto_bcryptencrypt]=apis.count("bcryptencrypt")!=0;
    out[F_api_crypto_bcryptdecrypt]=apis.count("bcryptdecrypt")!=0;
}
double count_entropy(const std::array<size_t,256> &counts,size_t length) {
    double value=0;if(!length)return value;
    for(const auto count:counts)if(count){const double p=double(count)/length;value-=p*std::log2(p);}return value;
}
bool magic(Span data,const char *needle,size_t length) {
    const auto first=reinterpret_cast<const uint8_t *>(needle);
    return length<=data.second && std::search(data.first,data.first+data.second,first,first+length)!=data.first+data.second;
}
size_t embedded_count(Span data) {
    size_t count=0;
    for(size_t i=0;i+64<=data.second;++i)if(data.first[i]=='M'&&data.first[i+1]=='Z'){
        const auto offset=read32(data,i+60);
        if(offset>=64&&offset<1048576&&offset<=data.second-i&&data.second-i-offset>=24&&read32(data,i+offset)==0x4550)++count;
    }return count;
}
uint32_t hash_bytes(const uint8_t *bytes,size_t length) {
    uint32_t value=2166136261u;for(size_t i=0;i<length;++i)value=(value^bytes[i])*16777619u;return value;
}
uint32_t hash_name(const std::string &name){return hash_bytes(reinterpret_cast<const uint8_t *>(name.data()),name.size());}
double quantile(const std::vector<double> &sorted,double q) {
    if(sorted.empty())return 0;const double position=q*(sorted.size()-1);const auto at=static_cast<size_t>(position);
    return sorted[at]+(sorted[std::min(at+1,sorted.size()-1)]-sorted[at])*(position-at);
}
void bytes(Span data,uint64_t total,double *out) {
    std::array<size_t,256> counts{},chunk{};std::vector<double> entropies,nz_entropies;
    size_t run=0,long_runs=0,zero_max=0,zero_long=0,zero_chunks=0;uint8_t previous=0;
    auto finish_run=[&]{if(run>=256){long_runs+=run;if(previous==0)zero_long+=run;}if(previous==0)zero_max=std::max(zero_max,run);};
    for(size_t i=0;i<data.second;++i){
        const auto b=data.first[i];++counts[b];++chunk[b];
        if(!run){previous=b;run=1;}else if(previous==b){++run;}else{finish_run();previous=b;run=1;}
        if((i+1)%65536==0||i+1==data.second){
            const size_t length=(i%65536)+1;entropies.push_back(count_entropy(chunk,length));
            if(length==65536&&chunk[0]==length)++zero_chunks;
            const size_t nz=length-chunk[0];chunk[0]=0;if(nz)nz_entropies.push_back(count_entropy(chunk,nz));chunk.fill(0);
        }
    }finish_run();
    const double n=double(std::max<size_t>(data.second,1)),file=double(std::max<uint64_t>(total,1));
    size_t dominant=0;for(size_t i=1;i<256;++i)if(counts[i]>counts[dominant])dominant=i;
    out[F_max_byte_value]=double(dominant);out[F_max_byte_ratio]=counts[dominant]/n;
    out[F_top_run_byte_ratio]=long_runs/file;out[F_zero_run_max_ratio]=zero_max/file;
    out[F_zero_in_long_runs_ratio]=double(zero_long)/std::max<size_t>(counts[0],1);
    out[F_zero_chunk_ratio]=double(zero_chunks)/std::max<size_t>(data.second/65536,1);
    out[F_chunk_count]=double(entropies.size());std::sort(entropies.begin(),entropies.end());
    out[F_chunk_entropy_p10]=quantile(entropies,.1);out[F_chunk_entropy_p50]=quantile(entropies,.5);out[F_chunk_entropy_p90]=quantile(entropies,.9);
    for(size_t i=0;i<256;++i)out[i/16]+=counts[i]/n;
    const size_t nz=data.second-counts[0];out[F_nz_count_log1p]=std::log1p(double(nz));counts[0]=0;
    out[F_nz_entropy]=count_entropy(counts,nz);size_t printable=counts[9]+counts[10]+counts[13],high=0,unique=0;
    for(size_t i=0;i<256;++i){if(i>=32&&i<=126)printable+=counts[i];if(i>=128)high+=counts[i];unique+=counts[i]!=0;}
    out[F_nz_printable_ratio]=double(printable)/std::max<size_t>(nz,1);out[F_nz_high_bit_ratio]=double(high)/std::max<size_t>(nz,1);out[F_nz_unique_byte_ratio]=double(unique)/256;
    if(!nz_entropies.empty()){
        double sum=0;for(const auto e:nz_entropies)sum+=e;const double mean=sum/nz_entropies.size();double variance=0;
        for(const auto e:nz_entropies)variance+=(e-mean)*(e-mean);
        out[F_nz_chunk_entropy_mean]=mean;out[F_nz_chunk_entropy_std]=std::sqrt(variance/nz_entropies.size());
        out[F_nz_chunk_entropy_min]=*std::min_element(nz_entropies.begin(),nz_entropies.end());out[F_nz_chunk_entropy_max]=*std::max_element(nz_entropies.begin(),nz_entropies.end());
    }
    std::array<size_t,16> nibble{};const size_t first=std::min<size_t>(2048,data.second);
    for(size_t i=0;i<first;++i)++nibble[data.first[i]>>4];double histogram_total=0;
    auto window=[&]{
        double e=0;for(const auto count:nibble)if(count){const double p=double(count)/2048;e-=p*std::log2(p);}
        const size_t bin=std::min<size_t>(15,static_cast<size_t>(e*4));
        for(size_t i=0;i<16;++i){out[F_byte_entropy_00_00+bin*16+i]+=double(nibble[i]);histogram_total+=double(nibble[i]);}
    };
    if(first)window();
    for(size_t at=1024;at+2048<=data.second;at+=1024){
        for(size_t i=at-1024;i<at;++i)--nibble[data.first[i]>>4];
        for(size_t i=at+1024;i<at+2048;++i)++nibble[data.first[i]>>4];window();
    }
    if(histogram_total)for(size_t i=0;i<256;++i)out[F_byte_entropy_00_00+i]/=histogram_total;
}
struct View {
    Span data;const Pe &pe;size_t optional;
    uint64_t read(size_t at,size_t width=4)const {
        if(at>data.second||width>data.second-at)return 0;uint64_t value=0;for(size_t i=0;i<width;++i)value|=uint64_t(data.first[at+i])<<(i*8);return value;
    }
    std::pair<uint32_t,uint32_t> directory(size_t index)const {
        const size_t relative=pe.magic==0x20b?112:96;
        if((pe.magic!=0x10b&&pe.magic!=0x20b)||relative+index*8+8>pe.optional_size||index>=read(optional+relative-4))return {0,0};
        return {static_cast<uint32_t>(read(optional+relative+index*8)),static_cast<uint32_t>(read(optional+relative+index*8+4))};
    }
    size_t map(uint64_t rva)const {
        for(const auto &s:pe.sections)if(rva>=s.va&&rva<uint64_t(s.va)+s.virtual_size&&rva-s.va<s.size&&uint64_t(s.offset)+rva-s.va<data.second)return s.offset+static_cast<size_t>(rva-s.va);
        return rva<read(optional+60)&&rva<data.second?static_cast<size_t>(rva):SIZE_MAX;
    }
    std::string string(size_t at,size_t limit=256)const {
        if(at>=data.second)return {};size_t length=0;while(length<limit&&length<data.second-at&&data.first[at+length])++length;
        return std::string(reinterpret_cast<const char *>(data.first+at),length);
    }
};
void pe_features(Span data,uint64_t total,const Pe &pe,double *out) {
    View v{data,pe,pe.pe+24};const auto o=v.optional;const double file=double(std::max<uint64_t>(total,1));
    const auto overlay=pe_overlay(data,total,pe);std::vector<Span> parts;
    if(overlay.certificate_size){parts.push_back(subspan(data,static_cast<size_t>(overlay.start),overlay.certificate-static_cast<size_t>(overlay.start)));parts.push_back(subspan(data,overlay.certificate+overlay.certificate_size,data.second));}
    else parts.push_back(subspan(data,static_cast<size_t>(overlay.start),data.second));
    size_t overlay_zero=0,overlay_length=0;
    for(const auto part:parts){
        overlay_length+=part.second;overlay_zero+=std::count(part.first,part.first+part.second,uint8_t(0));out[F_overlay_embedded_pe_count]+=double(embedded_count(part));
        out[F_overlay_magic_zip]=std::max(out[F_overlay_magic_zip],double(magic(part,"PK\x03\x04",4)||magic(part,"PK\x05\x06",4)||magic(part,"PK\x07\x08",4)));
        out[F_overlay_magic_7z]=std::max(out[F_overlay_magic_7z],double(magic(part,"7z\xbc\xaf\x27\x1c",6)));
        out[F_overlay_magic_rar]=std::max(out[F_overlay_magic_rar],double(magic(part,"Rar!\x1a\x07\x00",7)||magic(part,"Rar!\x1a\x07\x01\x00",8)));
        out[F_overlay_magic_nsis]=std::max(out[F_overlay_magic_nsis],double(magic(part,"NullsoftInst",12)));
        out[F_overlay_magic_inno]=std::max(out[F_overlay_magic_inno],double(magic(part,"Inno Setup Setup Data",21)||magic(part,"Inno Setup Messages",19)));
    }
    out[F_zero_ratio_overlay]=double(overlay_zero)/std::max<size_t>(overlay_length,1);
    out[F_embedded_pe_count]=double(embedded_count(data));if(out[F_embedded_pe_count]>0)--out[F_embedded_pe_count];
    out[F_packer_upx_magic]=magic(data,"UPX!",4);out[F_packer_themida]=magic(data,"Themida",7)||magic(data,"THEMIDA",7);
    out[F_packer_mpress]=magic(data,"MPRESS",6);out[F_packer_aspack]=magic(data,"ASPack",6);
    out[F_e_language_eapi_string]=magic(data,"eAPI",4)||magic(data,"EAPI",4);
    const std::set<std::string> standard={".text",".data",".rdata",".rsrc",".reloc",".bss",".idata",".edata",".tls",".pdata",".xdata",".debug"};
    size_t section_length=0,section_zero=0;double weighted=0;const uint64_t entry=v.read(o+16),image=v.read(o+56);bool entry_found=false;
    for(size_t i=0;i<pe.sections.size();++i){
        const auto &s=pe.sections[i];const auto name=lower(s.name);const auto block=subspan(data,s.offset,s.size);const double e=entropy(block);
        const auto declared_virtual=v.read(o+pe.optional_size+i*40+8);const double ratio=double(s.size)/std::max<uint64_t>(declared_virtual,1);
        section_length+=block.second;section_zero+=std::count(block.first,block.first+block.second,uint8_t(0));weighted+=e*block.second;
        if(i==0){out[F_section_entropy_min]=e;out[F_section_raw_virtual_ratio_min]=ratio;}
        out[F_section_entropy_max]=std::max(out[F_section_entropy_max],e);out[F_section_entropy_min]=std::min(out[F_section_entropy_min],e);
        out[F_section_raw_virtual_ratio_max]=std::max(out[F_section_raw_virtual_ratio_max],ratio);out[F_section_raw_virtual_ratio_min]=std::min(out[F_section_raw_virtual_ratio_min],ratio);
        if(name.rfind("upx",0)==0)out[F_packer_upx_section]=1;if(name==".vmp0"||name==".vmp1"||name==".vmp2")out[F_packer_vmprotect_section]=1;
        if(name==".themida")out[F_packer_themida]=1;if(name.rfind(".mpress",0)==0)out[F_packer_mpress]=1;if(name==".aspack"||name==".adata")out[F_packer_aspack]=1;
        if(!entry_found&&entry>=s.va&&entry<uint64_t(s.va)+s.virtual_size){
            entry_found=true;out[F_entry_section_entropy]=e;out[F_entry_section_is_last]=i+1==pe.sections.size();out[F_entry_section_name_standard]=standard.count(name)!=0;
            out[F_entry_section_relative_offset]=double(entry-s.va)/std::max<uint32_t>(s.virtual_size,1);
            const auto at=v.map(entry);if(at!=SIZE_MAX){const auto start=std::max<size_t>(s.offset,at>256?at-256:0);out[F_entry_pre256_entropy]=entropy(subspan(data,start,at-start));}
        }
    }
    out[F_zero_ratio_sections]=double(section_zero)/std::max<size_t>(section_length,1);out[F_section_entropy_weighted_mean]=weighted/std::max<size_t>(section_length,1);
    out[F_linker_major]=double(v.read(o+2,1));out[F_linker_minor]=double(v.read(o+3,1));out[F_os_major]=double(v.read(o+40,2));out[F_os_minor]=double(v.read(o+42,2));
    out[F_subsystem_major]=double(v.read(o+48,2));out[F_subsystem_minor]=double(v.read(o+50,2));
    out[F_code_size_ratio]=v.read(o+4)/file;out[F_initialized_data_size_ratio]=v.read(o+8)/file;out[F_uninitialized_data_size_ratio]=v.read(o+12)/file;
    const auto headers=v.read(o+60),alignment=v.read(o+36);
    out[F_headers_size_anomalous]=headers<o+pe.optional_size+v.read(pe.pe+6,2)*40||headers>total||!alignment||headers%alignment!=0;
    out[F_entry_rva_image_ratio]=double(entry)/std::max<uint64_t>(image,1);out[F_image_file_ratio]=image/file;
    const auto stamp=v.read(pe.pe+8);out[F_timestamp_before_1995]=stamp>0&&stamp<788918400;
    const auto tls_dir=v.directory(9),debug_dir=v.directory(6),reloc_dir=v.directory(5),config_dir=v.directory(10);
    out[F_tls_present]=tls_dir.first&&tls_dir.second;out[F_debug_directory_present]=debug_dir.first&&debug_dir.second;
    out[F_relocations_present]=reloc_dir.first&&reloc_dir.second;out[F_load_config_present]=config_dir.first&&config_dir.second;
    const size_t width=pe.magic==0x20b?8:4;const auto imagebase=v.read(o+(width==8?24:28),width);
    const auto tls=tls_dir.first?v.map(tls_dir.first):SIZE_MAX;
    if(tls!=SIZE_MAX){const auto address=v.read(tls+(width==8?24:12),width);const auto at=address>=imagebase?v.map(address-imagebase):SIZE_MAX;
        for(size_t i=0;at!=SIZE_MAX&&i<4096&&at<=data.second&&i*width+width<=data.second-at&&v.read(at+i*width,width);++i)++out[F_tls_callback_count];}
    const auto debug=debug_dir.first?v.map(debug_dir.first):SIZE_MAX;
    for(size_t i=0;debug!=SIZE_MAX&&i<std::min<size_t>(debug_dir.second/28,4096)&&debug<=data.second&&i*28+28<=data.second-debug;++i){
        const auto at=debug+i*28;if(v.read(at+12)!=2)continue;const auto q=static_cast<size_t>(v.read(at+24)),length=static_cast<size_t>(v.read(at+16));
        const auto sig=subspan(data,q,4);const size_t skip=starts(sig,"RSDS",4)?24:starts(sig,"NB10",4)?16:0;
        if(skip&&length>skip&&q<=data.second&&length<=data.second-q&&!v.string(q+skip,std::min<size_t>(length-skip,4096)).empty())out[F_pdb_path_present]=1;
    }
    size_t rich=SIZE_MAX;for(size_t i=0;i+4<=pe.pe&&i+4<=data.second;++i)if(read32(data,i)==0x68636952)rich=i;
    if(rich!=SIZE_MAX&&rich+8<=pe.pe){const auto key=read32(data,rich+4);size_t start=rich>=4?rich-4:0;
        while(start>=64&&(read32(data,start)^key)!=0x536e6144)start-=4;
        if(start>=64&&start+16<=rich){out[F_rich_header_present]=1;for(size_t i=start+16;i+8<=rich;i+=8){const uint32_t id=read32(data,i)^key;const uint8_t b[]={uint8_t(id),uint8_t(id>>8),uint8_t(id>>16),uint8_t(id>>24)};out[F_rich_hash_00+hash_bytes(b,4)%16]=1;}}
    }
    // Independent bits replace ordinal treatment of the two characteristic masks.
    const uint16_t dll_flags=static_cast<uint16_t>(v.read(o+70,2)),coff_flags=static_cast<uint16_t>(v.read(pe.pe+22,2));
    const unsigned dll_bits[]={0x20,0x40,0x80,0x100,0x400,0x1000,0x4000,0x8000};
    const unsigned coff_bits[]={1,2,4,8,0x20,0x100,0x200,0x400,0x800,0x1000,0x2000};
    for(size_t i=0;i<8;++i)out[F_dll_flag_high_entropy_va+i]=(dll_flags&dll_bits[i])!=0;
    for(size_t i=0;i<11;++i)out[F_coff_flag_relocs_stripped+i]=(coff_flags&coff_bits[i])!=0;
    std::set<std::string> apis,dlls;size_t total_imports=0,ordinals=0;
    for(const size_t index:{size_t(1),size_t(13)}){
        const auto dir=v.directory(index);const auto at=dir.first?v.map(dir.first):SIZE_MAX;const size_t step=index==1?20:32;
        const size_t limit=std::min<size_t>(512,dir.second?dir.second/step:512);
        for(size_t i=0;at!=SIZE_MAX&&i<limit&&at<=data.second&&i*step+step<=data.second-at;++i){
            const size_t d=at+i*step;if(std::all_of(data.first+d,data.first+d+step,[](uint8_t b){return !b;}))break;
            uint64_t name=v.read(d+(index==1?12:4)),thunk=index==1?(v.read(d)?v.read(d):v.read(d+16)):(v.read(d+16)?v.read(d+16):v.read(d+12));
            if(index==13&&!(v.read(d)&1)){name=name>=imagebase?name-imagebase:UINT64_MAX;thunk=thunk>=imagebase?thunk-imagebase:UINT64_MAX;}
            dlls.insert(lower(v.string(v.map(name),260)));const auto q=v.map(thunk);
            for(size_t j=0;q!=SIZE_MAX&&j<1024&&q<=data.second&&j*width+width<=data.second-q;++j){
                const auto value=v.read(q+j*width,width);if(!value)break;++total_imports;if(index==13)++out[F_delay_import_count];
                if(value&(uint64_t(1)<<(width*8-1))){++ordinals;continue;}const auto n=v.map(uint32_t(value));if(n!=SIZE_MAX)apis.insert(lower(v.string(n+2,254)));
            }
        }
    }
    out[F_import_ordinal_ratio]=double(ordinals)/std::max<size_t>(total_imports,1);
    const std::set<std::string> minimal={"getprocaddress","loadlibrarya","loadlibraryw","loadlibraryexa","loadlibraryexw"};
    out[F_import_minimal_flag]=!apis.empty()&&!ordinals&&apis.count("getprocaddress")&&apis.size()>1&&std::all_of(apis.begin(),apis.end(),[&](const std::string &a){return minimal.count(a)!=0;});
    for(const auto &name:apis)out[F_import_api_hash_000+hash_name(name)%128]=1;
    for(const auto &name:dlls){if(!name.empty())out[F_import_dll_hash_00+hash_name(name)%32]=1;if(name.find("krnln")!=std::string::npos)out[F_e_language_krnln_import]=1;}
    apply_api_flags(apis,out);
    const auto bound_dir=v.directory(11);size_t bound=bound_dir.first?v.map(bound_dir.first):SIZE_MAX;
    const auto bound_end=bound!=SIZE_MAX?std::min<uint64_t>(data.second,uint64_t(bound)+bound_dir.second):0;
    while(bound!=SIZE_MAX&&bound+8<=bound_end&&!std::all_of(data.first+bound,data.first+bound+8,[](uint8_t b){return !b;})){++out[F_bound_import_count];bound+=8*(1+v.read(bound+6,2));}
    const auto resource_dir=v.directory(2);const auto base=resource_dir.first?v.map(resource_dir.first):SIZE_MAX;
    std::set<std::pair<size_t,size_t>> visited,resources;std::set<uint32_t> icons,languages;
    auto walk=[&](auto &&self,size_t relative,size_t depth,uint32_t kind,uint32_t identity)->void{
        if(base==SIZE_MAX||depth>2||visited.size()>=4096||!visited.insert({relative,depth}).second||relative+16>resource_dir.second||relative>data.second-base||data.second-base-relative<16)return;
        const auto at=base+relative;const auto count=std::min<uint64_t>(4096,v.read(at+12,2)+v.read(at+14,2));
        for(size_t i=0;i<count;++i){
            const auto q=at+16+i*8;if(q+8>data.second||q+8>uint64_t(base)+resource_dir.second)break;const auto name=uint32_t(v.read(q)),child=uint32_t(v.read(q+4));
            const auto k=depth==0?name:kind,id=depth==1?name:identity;
            if(child&0x80000000u){self(self,child&0x7fffffffu,depth+1,k,id);continue;}
            if(uint64_t(child)+16>resource_dir.second||uint64_t(base)+child+16>data.second)continue;
            const auto leaf=base+child,offset=v.map(v.read(leaf));const auto length=v.read(leaf+4);if(offset==SIZE_MAX||!length)continue;
            resources.insert({offset,static_cast<size_t>(std::min<uint64_t>(length,data.second-offset))});if(k==3)icons.insert(id);if(depth==2&&!(name&0x80000000u))languages.insert(name);
        }
    };walk(walk,0,0,0,0);
    for(const auto &resource:resources){const auto block=subspan(data,resource.first,resource.second);out[F_resource_total_size_ratio]+=block.second/file;out[F_resource_max_entropy]=std::max(out[F_resource_max_entropy],entropy(block));out[F_resource_embedded_pe_count]+=double(embedded_count(block));}
    out[F_resource_embedded_pe_header]=out[F_resource_embedded_pe_count]>0;out[F_resource_icon_count]=double(icons.size());out[F_resource_language_id_count]=double(languages.size());
}
void extract(Span data,uint64_t total,const Pe &pe,const double *legacy,double *out) {
    std::fill(out,out+COUNT,0.0);size_t at=16;for(const auto index:LEGACY_INDICES)out[at++]=legacy[index];
    bytes(data,total,out);pe_features(data,total,pe,out);
}
} // namespace extended_ml

bool ml_raw_features(const double *features,size_t count,double *margins,size_t capacity) {
    if(!features||!margins||count!=silverfox_ml_model::FEATURE_COUNT||capacity<silverfox_ml_model::CLASS_COUNT)return false;
    for(size_t i=0;i<count;++i)if(!std::isfinite(features[i]))return false;
    std::fill(margins,margins+silverfox_ml_model::CLASS_COUNT,0.0);
    for (size_t tree=0;tree<silverfox_ml_model::TREE_COUNT;++tree) {
        const size_t base=silverfox_ml_model::TREE_OFFSETS[tree];std::int32_t node=0;
        for (;;) {
            const size_t at=base+static_cast<size_t>(node);const auto feature=silverfox_ml_model::FEATURES[at];
            if (feature<0) {margins[tree%silverfox_ml_model::CLASS_COUNT]+=silverfox_ml_model::LEAF_VALUES[at];break;}
            node=features[static_cast<size_t>(feature)]<=silverfox_ml_model::THRESHOLDS[at]?silverfox_ml_model::LEFT[at]:silverfox_ml_model::RIGHT[at];
        }
    }
    return true;
}
struct MlPrediction {double probability;size_t family;};
void ml_legacy_features(Span sample,uint64_t total_len,const Pe &pe,bool valid_pe,const uint32_t *gpu_histogram,size_t gpu_histogram_len,double *features) {
    std::fill(features,features+271+MODEL_METADATA_COUNT,0.0);
    if (!sample.second) {
        features[256]=std::log1p(static_cast<double>(total_len));
    } else {
        std::array<size_t,256> counts{};
        const size_t chunk_count=(sample.second+65535)/(64*1024);
        bool gpu_valid=gpu_histogram&&gpu_histogram_len==256*256&&chunk_count<=256;
        if(gpu_valid){
            for(size_t chunk=0;chunk<chunk_count;++chunk){
                uint64_t sum=0;for(size_t i=0;i<256;++i)sum+=gpu_histogram[chunk*256+i];
                const size_t length=std::min<size_t>(64*1024,sample.second-chunk*64*1024);
                if(sum!=length){gpu_valid=false;break;}
            }
        }
        if(gpu_valid){for(size_t chunk=0;chunk<chunk_count;++chunk)for(size_t i=0;i<256;++i)counts[i]+=gpu_histogram[chunk*256+i];}
        else{for(size_t i=0;i<sample.second;++i)++counts[sample.first[i]];}
        size_t printable=counts[9]+counts[10]+counts[13],zero=counts[0],high=0;
        for(size_t i=32;i<=126;++i)printable+=counts[i];for(size_t i=128;i<256;++i)high+=counts[i];
        size_t unique=0;for (size_t i=0;i<counts.size();++i) {features[i]=double(counts[i])/sample.second;unique+=size_t(counts[i]!=0);}
        std::vector<double> chunks;
        if(gpu_valid){for(size_t chunk=0;chunk<chunk_count;++chunk){const size_t length=std::min<size_t>(64*1024,sample.second-chunk*64*1024);double value=0;for(size_t i=0;i<256;++i){const auto count=gpu_histogram[chunk*256+i];if(count){const double p=double(count)/length;value-=p*std::log2(p);}}chunks.push_back(value);}}
        else{for (size_t start=0;start<sample.second;start+=64*1024) chunks.push_back(entropy(subspan(sample,start,64*1024)));}
        double chunk_sum=0,chunk_min=chunks.front(),chunk_max=chunks.front();
        for (auto value:chunks) {chunk_sum+=value;chunk_min=std::min(chunk_min,value);chunk_max=std::max(chunk_max,value);}
        double chunk_mean=chunk_sum/chunks.size(),variance=0;
        for (auto value:chunks) {auto delta=value-chunk_mean;variance+=delta*delta;}
        double global_entropy=0;for(auto count:counts)if(count){const double p=double(count)/sample.second;global_entropy-=p*std::log2(p);}
        features[256]=std::log1p(static_cast<double>(total_len));
        features[257]=global_entropy;features[258]=chunk_mean;features[259]=std::sqrt(variance/chunks.size());
        features[260]=chunk_min;features[261]=chunk_max;features[262]=double(printable)/sample.second;
        features[263]=double(zero)/sample.second;features[264]=double(high)/sample.second;features[265]=double(unique)/256.0;
    }
    features[266]=starts(sample,"MZ",2)?1.0:0.0;features[267]=valid_pe?1.0:0.0;
    features[268]=static_cast<double>(pe.sections.size());
    if (!pe.sections.empty()) {
        size_t executable=0;for (auto &section:pe.sections) executable+=size_t(section.executable);
        features[269]=double(executable)/pe.sections.size();
    }
    if (valid_pe) features[270]=double(pe_overlay(sample,total_len,pe).size)/std::max<uint64_t>(total_len,1);
    if(valid_pe){
        std::array<double,PE_METADATA_COUNT> metadata{};
        pe_metadata(sample,total_len,pe,metadata.data());
        size_t target=271;
        for(size_t source=0;source<PE_METADATA_COUNT;++source)
            if(std::find(EXCLUDED_MODEL_METADATA.begin(),EXCLUDED_MODEL_METADATA.end(),source)==EXCLUDED_MODEL_METADATA.end())
                features[target++]=metadata[source];
    }
}
MlPrediction ml_predict(Span sample,uint64_t total_len,const Pe &pe,bool valid_pe,const uint32_t *gpu_histogram,size_t gpu_histogram_len) {
    static_assert(silverfox_ml_model::FEATURE_COUNT==327 || silverfox_ml_model::FEATURE_COUNT==silverfox_features::COUNT,"model feature schema differs from native extractor");
    std::array<double,327> legacy{};
    ml_legacy_features(sample,total_len,pe,valid_pe,gpu_histogram,gpu_histogram_len,legacy.data());
    std::array<double,silverfox_ml_model::FEATURE_COUNT> features{};
    if constexpr(silverfox_ml_model::FEATURE_COUNT==327){std::copy(legacy.begin(),legacy.end(),features.begin());}
    else{extended_ml::extract(sample,total_len,pe,legacy.data(),features.data());}
    std::array<double,silverfox_ml_model::CLASS_COUNT> margins{};
    if(!ml_raw_features(features.data(),features.size(),margins.data(),margins.size()))return {-1.0,0};
    const double largest=*std::max_element(margins.begin(),margins.end());
    double total=0;for(const auto margin:margins)total+=std::exp(margin-largest);
    const double raw=std::clamp(1.0-std::exp(margins[0]-largest)/total,1e-7,1.0-1e-7);
    const double logit=std::clamp(silverfox_ml_model::CALIBRATION_SLOPE*std::log(raw/(1.0-raw))+silverfox_ml_model::CALIBRATION_INTERCEPT,-40.0,40.0);
    const double probability=logit>=0?1.0/(1.0+std::exp(-logit)):std::exp(logit)/(1.0+std::exp(logit));
    const auto family=static_cast<size_t>(std::max_element(margins.begin()+1,margins.end())-margins.begin());
    return {probability,family};
}
double ml_probability(Span sample,uint64_t total_len,const Pe &pe,bool valid_pe,const uint32_t *gpu_histogram,size_t gpu_histogram_len) {
    return ml_predict(sample,total_len,pe,valid_pe,gpu_histogram,gpu_histogram_len).probability;
}
void add(std::vector<Signal> &signals,const char *id,Category category,Strength strength,unsigned score,std::string detail) {
    signals.push_back({id,category,strength,std::min(score,100u),std::move(detail)});
}
template <typename... Args> std::string fmt(const char *format,Args... args) {
    int n=std::snprintf(nullptr,0,format,args...);if (n<=0 || n>4096) return {};
    std::string s(size_t(n),'\0');std::snprintf(s.data(),s.size()+1,format,args...);return s;
}
void put_text(char *dest,size_t capacity,const std::string &text) {
    if (!capacity) return;size_t n=std::min(capacity-1,text.size());
    // Do not split a UTF-8 codepoint at the fixed ABI boundary.
    while (n && n<text.size() && (static_cast<unsigned char>(text[n])&0xC0)==0x80) --n;
    std::memcpy(dest,text.data(),n);dest[n]=0;
}
bool attack(Category c) {return c==Category::Execution||c==Category::Persistence||c==Category::Injection||c==Category::SideLoad||c==Category::Miner||c==Category::Masquerade;}
void decide(const std::vector<Signal> &raw,SF_Result &out) {
    std::map<std::pair<std::string,Category>,Signal> unique;
    for (auto &s:raw) {
        auto key=std::make_pair(s.id,s.category);auto it=unique.find(key);
        if (it==unique.end() || int(s.strength)>int(it->second.strength) || (s.strength==it->second.strength && s.score>it->second.score)) unique.insert_or_assign(key,s);
    }
    auto has=[&](Category c,Strength level) {for (auto &entry:unique) if (entry.second.category==c && int(entry.second.strength)>=int(level)) return true;return false;};
    bool runtime=has(Category::Location,Strength::Context)||has(Category::Persistence,Strength::Corroborating)||has(Category::Execution,Strength::Corroborating);
    bool integrity=has(Category::Integrity,Strength::Strong)&&(has(Category::Execution,Strength::Corroborating)||has(Category::Persistence,Strength::Corroborating)||has(Category::Injection,Strength::Corroborating));
    bool strong_attack=false,strong_other=false;std::set<std::string> attackers;
    for (auto &entry:unique) {auto &s=entry.second;
        if (attack(s.category) && int(s.strength)>=2) attackers.insert(s.id);
        if (attack(s.category) && s.strength==Strength::Strong) strong_attack=true;
        if (s.category!=Category::Capability && s.strength==Strength::Strong) strong_other=true;
    }
    bool malicious=has(Category::Family,Strength::Strong)||(has(Category::Miner,Strength::Strong)&&runtime)||(has(Category::SideLoad,Strength::Strong)&&runtime)||integrity||(strong_attack&&attackers.size()>=2);
    bool suspicious=!malicious&&(strong_other||attackers.size()>=2||(has(Category::Packing,Strength::Corroborating)&&has(Category::Location,Strength::Context))||(has(Category::SideLoad,Strength::Corroborating)&&runtime));
    out.verdict=malicious?2:suspicious?1:0;out.score=malicious?85:suspicious?40:0;out.evidence_count=0;
    if (!out.verdict) {put_text(out.evidence[out.evidence_count++],sizeof(out.evidence[0]),"未发现能够闭合成攻击链的独立证据");return;}
    for (auto &entry:unique) {auto &s=entry.second;
        if ((malicious && s.strength==Strength::Strong)||(!malicious && int(s.strength)>=2)) out.score=std::max<uint16_t>(out.score,static_cast<uint16_t>(s.score));
        if ((s.category!=Category::Capability || int(s.strength)>=2) && out.evidence_count<32) put_text(out.evidence[out.evidence_count++],sizeof(out.evidence[0]),s.detail);
    }
    if (suspicious) out.score=std::min<uint16_t>(out.score,79);
}
} // namespace

extern "C" __declspec(dllexport) int __cdecl sf_ml_raw_features(const double *features,size_t count,double *out,size_t capacity) {
    return ml_raw_features(features,count,out,capacity)?int(silverfox_ml_model::CLASS_COUNT):0;
}

extern "C" __declspec(dllexport) uint32_t __cdecl sf_engine_abi() {return 3;}
extern "C" __declspec(dllexport) int __cdecl sf_pe_overlay_info(const uint8_t *bytes,size_t length,uint64_t total_len,double *out,size_t capacity) {
    if(!bytes||!out||length>256ull*1024*1024||capacity<4)return 0;
    Pe pe{};Span sample{bytes,length};if(!parse_pe(sample,pe))return 0;
    const auto info=pe_overlay(sample,total_len,pe);
    out[0]=double(info.start);out[1]=double(info.size);out[2]=double(info.certificate);out[3]=double(info.certificate_size);return 4;
}
extern "C" __declspec(dllexport) int __cdecl sf_extract_pe_metadata(const uint8_t *bytes,size_t length,uint64_t total_len,double *out,size_t capacity) {
    if(!bytes||!out||length>256ull*1024*1024||capacity<PE_METADATA_COUNT)return 0;
    Pe pe{};Span sample{bytes,length};if(!parse_pe(sample,pe))return 0;
    pe_metadata(sample,total_len,pe,out);return int(PE_METADATA_COUNT);
}
extern "C" __declspec(dllexport) int __cdecl sf_extract_pe_metadata_context(const uint8_t *bytes,size_t length,uint64_t total_len,const char *path,const char *const *siblings,size_t sibling_count,double *out,size_t capacity){
    if(!bytes||!out||length>256ull*1024*1024||capacity<PE_METADATA_COUNT||sibling_count>64)return 0;
    Pe pe{};Span sample{bytes,length};if(!parse_pe(sample,pe))return 0;
    (void)path;(void)siblings;pe_metadata(sample,total_len,pe,out);return int(PE_METADATA_COUNT);
}
// Extraction ABI is independent of the currently embedded model's dimensions.
extern "C" __declspec(dllexport) size_t __cdecl sf_extended_feature_count(){return silverfox_features::COUNT;}
extern "C" __declspec(dllexport) unsigned __cdecl sf_feature_schema_version(){return 2;}
extern "C" __declspec(dllexport) int __cdecl sf_extract_extended_features(const uint8_t *bytes,size_t length,uint64_t total_len,double *out,size_t capacity){
    if(!bytes||!out||length>256ull*1024*1024||capacity<silverfox_features::COUNT)return 0;
    Pe pe{};Span sample{bytes,length};if(!parse_pe(sample,pe))return 0;
    std::array<double,327> legacy{};ml_legacy_features(sample,total_len,pe,true,nullptr,0,legacy.data());
    extended_ml::extract(sample,total_len,pe,legacy.data(),out);return int(silverfox_features::COUNT);
}
extern "C" __declspec(dllexport) double __cdecl sf_ml_probability(const uint8_t *bytes,size_t length,uint64_t total_len) {
    if(!bytes||length>256ull*1024*1024||total_len<silverfox_ml_model::MIN_FILE_BYTES)return 0.0;
    Pe pe{};Span sample{bytes,length};if(!parse_pe(sample,pe))return 0.0;
    return ml_probability(sample,total_len,pe,true,nullptr,0);
}
extern "C" __declspec(dllexport) double __cdecl sf_ml_probability_context(const uint8_t *bytes,size_t length,uint64_t total_len,const char *path,const char *const *siblings,size_t sibling_count){
    if(!bytes||length>256ull*1024*1024||sibling_count>64||total_len<silverfox_ml_model::MIN_FILE_BYTES)return 0.0;
    Pe pe{};Span sample{bytes,length};if(!parse_pe(sample,pe))return 0.0;
    (void)path;(void)siblings;
    return ml_probability(sample,total_len,pe,true,nullptr,0);
}
extern "C" __declspec(dllexport) const char * __cdecl sf_engine_version() {return "2026.10.10.1";}

#include "configuration_scan.h"

// PE verdicts use LightGBM content features. PNG scanning checks payloads
// appended after IEND.
extern "C" __declspec(dllexport) int __cdecl sf_scan_file(const SF_FileInput *input,SF_Result *out) {
    if(!input||!out||input->abi!=3||!input->path||(!input->sample&&input->sample_len)||input->sample_len>256ull*1024*1024||
       (input->gpu_ml_histogram_len!=0&&input->gpu_ml_histogram_len!=256*256))return 0;
    std::memset(out,0,sizeof(*out));
    Span sample{input->sample,input->sample_len};Pe pe{};
    if(!parse_pe(sample,pe)) {
        constexpr char PNG[]={static_cast<char>(0x89),'P','N','G','\r','\n',static_cast<char>(0x1a),'\n'};
        if(starts(sample,PNG,sizeof(PNG))) {
            size_t at=8;
            while(at<=sample.second && sample.second-at>=12) {
                uint32_t length=read_be32(sample,at);
                if(length>sample.second-at-12)break;
                const bool iend=length==0 && std::memcmp(sample.first+at+4,"IEND",4)==0;
                at+=12+length;
                if(iend) {
                    const uint64_t tail=input->total_len>at?input->total_len-at:0;
                    Span overlay=subspan(sample,at,std::min<size_t>(1048576,sample.second-at));
                    const double overlay_entropy=overlay.second>=4096?entropy(overlay):0.0;
                    if(tail>=65536 && tail>=input->total_len/2 && overlay.second>=4096 &&
                       (overlay_entropy>7.5 || starts(overlay,"MZ",2) || starts(overlay,"PK",2))) {
                        const bool strong_overlay=tail>=256*1024 && tail>=input->total_len*9/10 && overlay_entropy>7.95;
                        out->verdict=strong_overlay?2:1;out->score=strong_overlay?99:75;
                        put_text(out->evidence[out->evidence_count++],sizeof(out->evidence[0]),fmt("Stego.PNG.Overlay：IEND 后偏移 0x%llx 存在 %llu 字节附加数据（熵 %.3f）。",static_cast<unsigned long long>(at),static_cast<unsigned long long>(tail),overlay_entropy));
                    }
                    break;
                }
            }
            if(out->verdict)return 1;
        }
        out->verdict=3;
        put_text(out->evidence[out->evidence_count++],sizeof(out->evidence[0]),"非 PE 文件未命中受支持的专项检测；没有通用非 PE 机器学习模型");
        return 1;
    }
    if(input->total_len<silverfox_ml_model::MIN_FILE_BYTES) {
        out->verdict=3;
        put_text(out->evidence[out->evidence_count++],sizeof(out->evidence[0]),"扫描的文件至少需要 2KB");
        return 1;
    }
    const auto prediction=ml_predict(sample,input->total_len,pe,true,input->gpu_ml_histogram,input->gpu_ml_histogram_len);
    if(prediction.probability<0)return 0;
    const double probability=prediction.probability;
    const char *family=silverfox_ml_model::CLASS_NAMES[prediction.family];
    const unsigned confidence=static_cast<unsigned>(std::clamp(std::lround(probability*200.0),0L,200L));
    if(probability>=silverfox_ml_model::MALICIOUS_THRESHOLD) {
        out->verdict=2;out->score=static_cast<uint16_t>(std::clamp(std::round(probability*100.0),0.0,100.0));
        put_text(out->evidence[out->evidence_count++],sizeof(out->evidence[0]),fmt("Trojan.%s.%02X",family,confidence));
    }else if(probability>=silverfox_ml_model::SUSPICIOUS_THRESHOLD) {
        out->verdict=1;out->score=static_cast<uint16_t>(std::clamp(std::round(probability*100.0),0.0,100.0));
        put_text(out->evidence[out->evidence_count++],sizeof(out->evidence[0]),fmt("Trojan.%s.%02X",family,confidence));
    }
    return 1;
}


// These ABI entry points return neutral results for name and module metadata.
extern "C" __declspec(dllexport) int __cdecl sf_random_process_name(const char *) {return 0;}
extern "C" __declspec(dllexport) int __cdecl sf_dual_use_remote_process(const char *) {return 0;}
extern "C" __declspec(dllexport) int __cdecl sf_sideloaded_module(const char *,const char *,int,int,int,SF_Result *out) {
    if(!out)return 0;
    std::memset(out,0,sizeof(*out));return 1;
}

extern "C" __declspec(dllexport) int __cdecl sf_is_windows_path(const char *path) {
    return path && windows_path(path);
}
extern "C" __declspec(dllexport) int __cdecl sf_is_user_writable_path(const char *path) {
    return path && user_writable_path(path);
}
extern "C" __declspec(dllexport) int __cdecl sf_directory_hidden_system(const char *path) {
    return path && concealed_directory(path);
}
extern "C" __declspec(dllexport) int __cdecl sf_signature_untrusted(const char *status) {
    if (!status) return 0;
    auto s=std::string(status);
    for (auto prefix:{"未签名","签名无效","签名未受信任","签名已过期","检测失败"})
        if (s.compare(0,std::strlen(prefix),prefix)==0) return 1;
    return 0;
}
extern "C" __declspec(dllexport) int __cdecl sf_hosted_duty_idle(const char *const *,size_t,const char *const *,size_t,int,int) {return 0;}

extern "C" __declspec(dllexport) int __cdecl sf_assess_service_host(const SF_ServiceInput *input,SF_ServiceResult *out) {
    if (!input || !out) return 0;
    std::memset(out,0,sizeof(*out));
    if (!(input->cpu_share_percent>=12.0f) || !std::isfinite(input->cpu_share_percent) || input->sample_seconds<4) return 1;
    auto &finding=out->finding;
    auto append_evidence=[&](const std::string &s) {if (finding.evidence_count<32) put_text(finding.evidence[finding.evidence_count++],sizeof(finding.evidence[0]),s);};
    auto append_cleanup=[&](const std::string &s) {if (out->cleanup_count<12) put_text(out->cleanup[out->cleanup_count++],sizeof(out->cleanup[0]),s);};
    append_evidence(fmt("服务宿主占用全机 CPU %.1f%%（%u 秒窗口），承载 %llu 个服务；占用仅作为排查筛选，不作为判定依据",input->cpu_share_percent,input->sample_seconds,static_cast<unsigned long long>(input->hosted_service_count)));
    int attribution=0;
    if (input->unbacked_modules) {++attribution;append_evidence(fmt("宿主加载了 %llu 个位于 Windows 目录之外的模块（模块清单已逐项列出），这是可归因的注入/侧加载证据",static_cast<unsigned long long>(input->unbacked_modules)));}
    if (input->untrusted_service_images || input->orphaned_services || input->unbacked_services) {
        ++attribution;
        append_evidence(fmt("宿主承载的服务注册异常：Windows 目录外映像 %llu 个、未受信签名 %llu 个、映像缺失 %llu 个",static_cast<unsigned long long>(input->unbacked_services),static_cast<unsigned long long>(input->untrusted_service_images),static_cast<unsigned long long>(input->orphaned_services)));
    }
    if (!attribution && !input->duty_mismatch) {std::memset(out,0,sizeof(*out));return 1;}
    if (!attribution) {
        append_evidence("该宿主承载的服务按功能可验证地空闲（无已配置的 RAS/VPN 连接项且无相关客户端进程），占用无法由其自身职责解释；但未能在宿主内归因到任何非系统模块或注入代码");
        append_evidence("结论：这是需要进一步归因的观察项（建议对忙线程做 ETW/栈采样以定位调用方），不作为恶意结论");
    }
    finding.verdict=attribution>=2?2:1;
    finding.score=attribution>=2?90:attribution?75:60;
    append_cleanup(fmt("不终止服务宿主进程：同一宿主承载 %llu 个服务，结束进程会连带破坏其它服务并销毁现场",static_cast<unsigned long long>(input->hosted_service_count)));
    append_cleanup(fmt("记录处置前基线：宿主 CPU 占比 %.1f%%（%u 秒采样），作为回测对照",input->cpu_share_percent,input->sample_seconds));
    if (input->orphaned_services) append_cleanup(fmt("删除 %llu 个注册残留服务（映像已缺失，注册项仍存在）",static_cast<unsigned long long>(input->orphaned_services)));
    if (input->untrusted_service_images) append_cleanup(fmt("停止并删除 %llu 个注册未受信映像的服务",static_cast<unsigned long long>(input->untrusted_service_images)));
    if (input->duty_mismatch) append_cleanup("逐个重启被滥用的正常服务（按服务名停止/启动，宿主进程保持运行），而不是结束宿主");
    append_cleanup("移除持久化并重启相关服务后重新采样：CPU 回落至基线即确认滥用来自外部持久化，处置完成");
    if (finding.verdict==2) append_cleanup("若清理后 CPU 仍持续偏高，标记为需重启后复查并保留现场，不升级为结束系统进程");
    return 1;
}
