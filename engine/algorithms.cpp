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
    size_t overlay=pe.raw_end<data.second?size_t(pe.raw_end):data.second;
    v[43]=std::log1p(double(total_len>pe.raw_end?total_len-pe.raw_end:0));
    if(overlay<data.second) {Span ov=subspan(data,overlay,std::min<size_t>(data.second-overlay,1048576));v[44]=entropy(ov);size_t printable=0;for(size_t i=0;i<ov.second;i++)printable+=ov.first[i]>=32&&ov.first[i]<=126;v[45]=double(printable)/ov.second;v[46]=starts(ov,"MZ",2)||starts(ov,"PK",2);}
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
MlPrediction ml_predict(Span sample,uint64_t total_len,const Pe &pe,bool valid_pe,const uint32_t *gpu_histogram,size_t gpu_histogram_len) {
    std::array<double,271+MODEL_METADATA_COUNT> features{};
    static_assert(silverfox_ml_model::FEATURE_COUNT==271+MODEL_METADATA_COUNT,"model feature count differs from native extractor");
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
    if (valid_pe) features[270]=double(total_len>pe.raw_end?total_len-pe.raw_end:0)/std::max<uint64_t>(total_len,1);
    if(valid_pe){
        std::array<double,PE_METADATA_COUNT> metadata{};
        pe_metadata(sample,total_len,pe,metadata.data());
        size_t target=271;
        for(size_t source=0;source<PE_METADATA_COUNT;++source)
            if(std::find(EXCLUDED_MODEL_METADATA.begin(),EXCLUDED_MODEL_METADATA.end(),source)==EXCLUDED_MODEL_METADATA.end())
                features[target++]=metadata[source];
    }
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
extern "C" __declspec(dllexport) const char * __cdecl sf_engine_version() {return "2026.10.6.1";}

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
