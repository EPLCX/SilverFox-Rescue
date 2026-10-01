#![allow(dead_code)] // Optional GPU prefilter entry points.
use anyhow::{bail, Result};
use std::{ptr::null_mut, sync::{Mutex, OnceLock}};
use winapi::{
    ctypes::c_void,
    shared::{dxgiformat::{DXGI_FORMAT_R32_TYPELESS, DXGI_FORMAT_UNKNOWN}, winerror::SUCCEEDED},
    um::{
        d3d11::{
            D3D11CreateDevice, ID3D11Buffer, ID3D11ComputeShader, ID3D11Device,
            ID3D11DeviceContext, ID3D11ShaderResourceView, ID3D11UnorderedAccessView,
            D3D11_BIND_CONSTANT_BUFFER, D3D11_BIND_SHADER_RESOURCE, D3D11_BIND_UNORDERED_ACCESS, D3D11_BOX, D3D11_BUFFEREX_SRV,
            D3D11_BUFFEREX_SRV_FLAG_RAW, D3D11_BUFFER_DESC, D3D11_BUFFER_UAV,
            D3D11_CPU_ACCESS_READ, D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE,
            D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS, D3D11_RESOURCE_MISC_BUFFER_STRUCTURED,
            D3D11_SDK_VERSION, D3D11_SHADER_RESOURCE_VIEW_DESC,
            D3D11_UNORDERED_ACCESS_VIEW_DESC, D3D11_UAV_DIMENSION_BUFFER,
            D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
        },
        d3dcommon::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL, D3D_FEATURE_LEVEL_11_0, D3D_SRV_DIMENSION_BUFFEREX},
    },
};

const PATTERN_SHADER: &[u8] = include_bytes!("../shaders/patterns.cso");
const ENTROPY_SHADER: &[u8] = include_bytes!("../shaders/entropy.cso");
// Below this size the upload/dispatch/synchronous readback overhead is usually
// larger than the CPU search that the prefilter replaces.
const GPU_MIN_BYTES: usize = 256 * 1024;
const GPU_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATTERNS: usize = 64;
const MAX_PATTERN_BYTES: usize = 4096;
const ML_OUTPUT_WORDS:usize=256*256;

enum GpuState {
    Available(Mutex<GpuEntropy>),
    Unavailable(String),
}

static GPU: OnceLock<GpuState> = OnceLock::new();

pub fn initialize() {
    let state=GPU.get_or_init(|| match unsafe { GpuEntropy::new() } {
        Ok(engine) => GpuState::Available(Mutex::new(engine)),
        Err(error) => GpuState::Unavailable(error.to_string()),
    });
    // Device creation alone can remain completely idle in task-manager.  Run a
    // bounded, real dispatch once at scan-engine startup so driver/shader
    // initialization happens before the first file and the chosen adapter is
    // genuinely ready for the high-volume prefilter.
    if crate::settings::load().gpu!="disabled" {
        if let GpuState::Available(engine)=state {
            if let Ok(mut engine)=engine.lock(){let _=engine.warm_up();}
        }
    }
}

pub fn status() -> String {
    if crate::settings::load().gpu=="disabled" {
        return "DX11 GPU 加速已按设置禁用（使用 CPU 扫描）".into();
    }
    match GPU.get_or_init(|| match unsafe { GpuEntropy::new() } {
        Ok(engine) => GpuState::Available(Mutex::new(engine)),
        Err(error) => GpuState::Unavailable(error.to_string()),
    }) {
        GpuState::Available(_) => "DX11 GPU 加速已启用（ML 分块熵与字节频率由 Compute Shader 提取）".into(),
        GpuState::Unavailable(reason) => format!("DX11 GPU 加速不可用，已回退 CPU：{reason}"),
    }
}

pub fn pattern_hits(data:&[u8],patterns:&[&[u8]])->Option<Vec<bool>>{
    if crate::settings::load().gpu=="disabled"{return None;}
    if data.len()<GPU_MIN_BYTES||patterns.is_empty()||patterns.len()>MAX_PATTERNS||patterns.iter().any(|pattern|pattern.is_empty()||pattern.len()>128)||patterns.iter().map(|pattern|pattern.len()).sum::<usize>()>MAX_PATTERN_BYTES{return None;}
    match GPU.get_or_init(||match unsafe{GpuEntropy::new()}{Ok(engine)=>GpuState::Available(Mutex::new(engine)),Err(error)=>GpuState::Unavailable(error.to_string())}){
        GpuState::Available(engine)=>engine.lock().ok()?.pattern_hits(data,patterns).ok(),
        GpuState::Unavailable(_)=>None,
    }
}

/// Run the shared high-volume signature prefilter.  The authoritative verdict
/// still comes from the signed algorithm engine; this pass supplies the GPU
/// work and lets the engine avoid repeating obvious byte searches.
pub fn prefilter(data:&[u8])->Option<u64> {
    const PATTERNS:&[&[u8]]=&[
        b"ValleyRat", b"GetVolumeInformationW", b"WinHttpOpen",
        b"RegSetValueExW", b"VirtualAllocEx", b"WriteProcessMemory",
        b"CreateRemoteThread", b"schtasks.exe", b"/create", b"powershell", b"-enc",
    ];
    let hits=pattern_hits(data,PATTERNS)?;
    Some(hits.into_iter().enumerate().fold(0u64,|mask,(index,hit)|if hit{mask|(1u64<<index)}else{mask}))
}
/// Computes the 256-bin byte histogram used by ML features on the GPU.
pub fn ml_histograms(data:&[u8])->Option<Vec<u32>>{
    if crate::settings::load().gpu=="disabled"||data.len()<GPU_MIN_BYTES||data.len()>GPU_BUFFER_BYTES{return None;}
    match GPU.get_or_init(||match unsafe{GpuEntropy::new()}{Ok(engine)=>GpuState::Available(Mutex::new(engine)),Err(error)=>GpuState::Unavailable(error.to_string())}){
        GpuState::Available(engine)=>engine.lock().ok()?.histograms(data).ok(),GpuState::Unavailable(_)=>None,
    }
}

struct GpuEntropy {
    device: *mut ID3D11Device,
    context: *mut ID3D11DeviceContext,
    pattern_shader: *mut ID3D11ComputeShader,
    entropy_shader:*mut ID3D11ComputeShader,
    input: *mut ID3D11Buffer,
    srv: *mut ID3D11ShaderResourceView,
    pattern_bytes:*mut ID3D11Buffer,
    pattern_meta:*mut ID3D11Buffer,
    pattern_hits_buffer:*mut ID3D11Buffer,
    pattern_staging:*mut ID3D11Buffer,
    pattern_parameters:*mut ID3D11Buffer,
    pattern_srv:*mut ID3D11ShaderResourceView,
    pattern_meta_srv:*mut ID3D11ShaderResourceView,
    pattern_uav:*mut ID3D11UnorderedAccessView,
    histogram_buffer:*mut ID3D11Buffer,histogram_staging:*mut ID3D11Buffer,
    histogram_parameters:*mut ID3D11Buffer,histogram_uav:*mut ID3D11UnorderedAccessView,
}

unsafe impl Send for GpuEntropy {}

impl GpuEntropy {
    unsafe fn new() -> Result<Self> {
        let mut device = null_mut();
        let mut context = null_mut();
        let mut level: D3D_FEATURE_LEVEL = 0;
        let levels = [D3D_FEATURE_LEVEL_11_0];
        let result = D3D11CreateDevice(
            null_mut(), D3D_DRIVER_TYPE_HARDWARE, null_mut(), 0, levels.as_ptr(),
            levels.len() as u32, D3D11_SDK_VERSION, &mut device, &mut level, &mut context,
        );
        if !SUCCEEDED(result) || device.is_null() || context.is_null() {
            bail!("D3D11CreateDevice 失败：0x{:08X}", result as u32);
        }
        let mut pattern_shader=null_mut();
        let result=(*device).CreateComputeShader(PATTERN_SHADER.as_ptr()as *const c_void,PATTERN_SHADER.len(),null_mut(),&mut pattern_shader);
        if !SUCCEEDED(result)||pattern_shader.is_null(){(*context).Release();(*device).Release();bail!("创建模式匹配 Compute Shader 失败：0x{:08X}",result as u32);}
        let mut entropy_shader=null_mut();let result=(*device).CreateComputeShader(ENTROPY_SHADER.as_ptr()as *const c_void,ENTROPY_SHADER.len(),null_mut(),&mut entropy_shader);
        if !SUCCEEDED(result)||entropy_shader.is_null(){(*pattern_shader).Release();(*context).Release();(*device).Release();bail!("创建 ML 特征 Compute Shader 失败：0x{:08X}",result as u32);}
        let mut engine = Self { device, context, pattern_shader,entropy_shader,input:null_mut(),srv:null_mut(),pattern_bytes:null_mut(),pattern_meta:null_mut(),pattern_hits_buffer:null_mut(),pattern_staging:null_mut(),pattern_parameters:null_mut(),pattern_srv:null_mut(),pattern_meta_srv:null_mut(),pattern_uav:null_mut(),histogram_buffer:null_mut(),histogram_staging:null_mut(),histogram_parameters:null_mut(),histogram_uav:null_mut() };
        engine.create_resources()?;
        engine.create_pattern_resources()?;
        engine.create_histogram_resources()?;
        Ok(engine)
    }

    unsafe fn create_histogram_resources(&mut self)->Result<()>{
        let output=D3D11_BUFFER_DESC{ByteWidth:(ML_OUTPUT_WORDS*4)as u32,Usage:D3D11_USAGE_DEFAULT,BindFlags:D3D11_BIND_UNORDERED_ACCESS,CPUAccessFlags:0,MiscFlags:D3D11_RESOURCE_MISC_BUFFER_STRUCTURED,StructureByteStride:4};
        let staging=D3D11_BUFFER_DESC{ByteWidth:(ML_OUTPUT_WORDS*4)as u32,Usage:D3D11_USAGE_STAGING,BindFlags:0,CPUAccessFlags:D3D11_CPU_ACCESS_READ,MiscFlags:0,StructureByteStride:4};
        let params=D3D11_BUFFER_DESC{ByteWidth:16,Usage:D3D11_USAGE_DEFAULT,BindFlags:D3D11_BIND_CONSTANT_BUFFER,CPUAccessFlags:0,MiscFlags:0,StructureByteStride:0};
        let result=(*self.device).CreateBuffer(&output,null_mut(),&mut self.histogram_buffer);if !SUCCEEDED(result){bail!("创建 GPU ML 直方图失败");}
        let result=(*self.device).CreateBuffer(&staging,null_mut(),&mut self.histogram_staging);if !SUCCEEDED(result){bail!("创建 GPU ML 回读缓冲区失败");}
        let result=(*self.device).CreateBuffer(&params,null_mut(),&mut self.histogram_parameters);if !SUCCEEDED(result){bail!("创建 GPU ML 参数缓冲区失败");}
        let mut desc:D3D11_UNORDERED_ACCESS_VIEW_DESC=std::mem::zeroed();desc.Format=DXGI_FORMAT_UNKNOWN;desc.ViewDimension=D3D11_UAV_DIMENSION_BUFFER;*desc.u.Buffer_mut()=D3D11_BUFFER_UAV{FirstElement:0,NumElements:ML_OUTPUT_WORDS as u32,Flags:0};
        let result=(*self.device).CreateUnorderedAccessView(self.histogram_buffer as *mut _,&desc,&mut self.histogram_uav);if !SUCCEEDED(result){bail!("创建 GPU ML 直方图视图失败");}Ok(())
    }

    unsafe fn create_resources(&mut self) -> Result<()> {
        let input_desc=D3D11_BUFFER_DESC{ByteWidth:GPU_BUFFER_BYTES as u32,Usage:D3D11_USAGE_DEFAULT,BindFlags:D3D11_BIND_SHADER_RESOURCE,CPUAccessFlags:0,MiscFlags:D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS,StructureByteStride:0};
        let result=(*self.device).CreateBuffer(&input_desc,null_mut(),&mut self.input);if !SUCCEEDED(result){bail!("创建可复用 GPU 输入缓冲区失败：0x{:08X}",result as u32);}
        let mut srv_desc:D3D11_SHADER_RESOURCE_VIEW_DESC=std::mem::zeroed();srv_desc.Format=DXGI_FORMAT_R32_TYPELESS;srv_desc.ViewDimension=D3D_SRV_DIMENSION_BUFFEREX;*srv_desc.u.BufferEx_mut()=D3D11_BUFFEREX_SRV{FirstElement:0,NumElements:(GPU_BUFFER_BYTES/4)as u32,Flags:D3D11_BUFFEREX_SRV_FLAG_RAW};
        let result=(*self.device).CreateShaderResourceView(self.input as *mut _,&srv_desc,&mut self.srv);if !SUCCEEDED(result){bail!("创建可复用 GPU 输入视图失败：0x{:08X}",result as u32);}
        Ok(())
    }

    unsafe fn create_pattern_resources(&mut self)->Result<()> {
        let pattern_desc=D3D11_BUFFER_DESC{ByteWidth:MAX_PATTERN_BYTES as u32,Usage:D3D11_USAGE_DEFAULT,BindFlags:D3D11_BIND_SHADER_RESOURCE,CPUAccessFlags:0,MiscFlags:D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS,StructureByteStride:0};
        let meta_desc=D3D11_BUFFER_DESC{ByteWidth:(MAX_PATTERNS*8)as u32,Usage:D3D11_USAGE_DEFAULT,BindFlags:D3D11_BIND_SHADER_RESOURCE,CPUAccessFlags:0,MiscFlags:D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS,StructureByteStride:0};
        let hits_desc=D3D11_BUFFER_DESC{ByteWidth:(MAX_PATTERNS*4)as u32,Usage:D3D11_USAGE_DEFAULT,BindFlags:D3D11_BIND_UNORDERED_ACCESS,CPUAccessFlags:0,MiscFlags:D3D11_RESOURCE_MISC_BUFFER_STRUCTURED,StructureByteStride:4};
        let staging_desc=D3D11_BUFFER_DESC{ByteWidth:hits_desc.ByteWidth,Usage:D3D11_USAGE_STAGING,BindFlags:0,CPUAccessFlags:D3D11_CPU_ACCESS_READ,MiscFlags:0,StructureByteStride:4};
        let parameters_desc=D3D11_BUFFER_DESC{ByteWidth:16,Usage:D3D11_USAGE_DEFAULT,BindFlags:D3D11_BIND_CONSTANT_BUFFER,CPUAccessFlags:0,MiscFlags:0,StructureByteStride:0};
        let result=(*self.device).CreateBuffer(&pattern_desc,null_mut(),&mut self.pattern_bytes);if !SUCCEEDED(result){bail!("创建 GPU 模式缓冲区失败：0x{:08X}",result as u32);}
        let result=(*self.device).CreateBuffer(&meta_desc,null_mut(),&mut self.pattern_meta);if !SUCCEEDED(result){bail!("创建 GPU 模式索引失败：0x{:08X}",result as u32);}
        let result=(*self.device).CreateBuffer(&hits_desc,null_mut(),&mut self.pattern_hits_buffer);if !SUCCEEDED(result){bail!("创建 GPU 命中缓冲区失败：0x{:08X}",result as u32);}
        let result=(*self.device).CreateBuffer(&staging_desc,null_mut(),&mut self.pattern_staging);if !SUCCEEDED(result){bail!("创建 GPU 命中回读缓冲区失败：0x{:08X}",result as u32);}
        let result=(*self.device).CreateBuffer(&parameters_desc,null_mut(),&mut self.pattern_parameters);if !SUCCEEDED(result){bail!("创建 GPU 模式参数缓冲区失败：0x{:08X}",result as u32);}
        let mut srv_desc:D3D11_SHADER_RESOURCE_VIEW_DESC=std::mem::zeroed();srv_desc.Format=DXGI_FORMAT_R32_TYPELESS;srv_desc.ViewDimension=D3D_SRV_DIMENSION_BUFFEREX;*srv_desc.u.BufferEx_mut()=D3D11_BUFFEREX_SRV{FirstElement:0,NumElements:(MAX_PATTERN_BYTES/4)as u32,Flags:D3D11_BUFFEREX_SRV_FLAG_RAW};
        let result=(*self.device).CreateShaderResourceView(self.pattern_bytes as *mut _,&srv_desc,&mut self.pattern_srv);if !SUCCEEDED(result){bail!("创建 GPU 模式视图失败：0x{:08X}",result as u32);}
        *srv_desc.u.BufferEx_mut()=D3D11_BUFFEREX_SRV{FirstElement:0,NumElements:(MAX_PATTERNS*2)as u32,Flags:D3D11_BUFFEREX_SRV_FLAG_RAW};
        let result=(*self.device).CreateShaderResourceView(self.pattern_meta as *mut _,&srv_desc,&mut self.pattern_meta_srv);if !SUCCEEDED(result){bail!("创建 GPU 模式索引视图失败：0x{:08X}",result as u32);}
        let mut uav_desc:D3D11_UNORDERED_ACCESS_VIEW_DESC=std::mem::zeroed();uav_desc.Format=DXGI_FORMAT_UNKNOWN;uav_desc.ViewDimension=D3D11_UAV_DIMENSION_BUFFER;*uav_desc.u.Buffer_mut()=D3D11_BUFFER_UAV{FirstElement:0,NumElements:MAX_PATTERNS as u32,Flags:0};
        let result=(*self.device).CreateUnorderedAccessView(self.pattern_hits_buffer as *mut _,&uav_desc,&mut self.pattern_uav);if !SUCCEEDED(result){bail!("创建 GPU 命中视图失败：0x{:08X}",result as u32);}
        Ok(())
    }

    fn pattern_hits(&mut self,data:&[u8],patterns:&[&[u8]])->Result<Vec<bool>> {unsafe{self.pattern_hits_inner(data,patterns)}}
    fn histograms(&mut self,data:&[u8])->Result<Vec<u32>>{unsafe{self.histograms_inner(data)}}

    unsafe fn histograms_inner(&mut self,data:&[u8])->Result<Vec<u32>>{
        let padded=(data.len()+3)&!3;let mut input=Vec::with_capacity(padded);input.extend_from_slice(data);input.resize(padded,0);
        let region=D3D11_BOX{left:0,top:0,front:0,right:padded as u32,bottom:1,back:1};(*self.context).UpdateSubresource(self.input as *mut _,0,&region,input.as_ptr()as *const c_void,0,0);
        let groups=((data.len()+65535)/65536)as u32;let params=[data.len()as u32,groups,0,0];(*self.context).UpdateSubresource(self.histogram_parameters as *mut _,0,null_mut(),params.as_ptr()as *const c_void,0,0);(*self.context).ClearUnorderedAccessViewUint(self.histogram_uav,&[0,0,0,0]);
        (*self.context).CSSetShader(self.entropy_shader,null_mut(),0);(*self.context).CSSetConstantBuffers(0,1,&self.histogram_parameters);(*self.context).CSSetShaderResources(0,1,&self.srv);(*self.context).CSSetUnorderedAccessViews(0,1,&self.histogram_uav,null_mut());(*self.context).Dispatch(groups,1,1);
        let null_srv:*mut ID3D11ShaderResourceView=null_mut();let null_uav:*mut ID3D11UnorderedAccessView=null_mut();(*self.context).CSSetShaderResources(0,1,&null_srv);(*self.context).CSSetUnorderedAccessViews(0,1,&null_uav,null_mut());(*self.context).CopyResource(self.histogram_staging as *mut _,self.histogram_buffer as *mut _);
        let mut mapped:D3D11_MAPPED_SUBRESOURCE=std::mem::zeroed();let result=(*self.context).Map(self.histogram_staging as *mut _,0,D3D11_MAP_READ,0,&mut mapped);if !SUCCEEDED(result){bail!("GPU ML 特征回读失败");}let out=std::slice::from_raw_parts(mapped.pData as *const u32,ML_OUTPUT_WORDS).to_vec();(*self.context).Unmap(self.histogram_staging as *mut _,0);Ok(out)
    }

    fn warm_up(&mut self)->Result<()> {
        let data=vec![0u8;1024*1024];
        let patterns:[&[u8];1]=[b"silverfox-gpu-warmup"];
        self.pattern_hits(&data,&patterns).map(|_|())
    }

    unsafe fn pattern_hits_inner(&mut self,data:&[u8],patterns:&[&[u8]])->Result<Vec<bool>>{
        if data.len()>GPU_BUFFER_BYTES{bail!("GPU 模式扫描输入超过 16 MB");}
        let input_length=(data.len()+3)&!3;let mut input=Vec::with_capacity(input_length);input.extend_from_slice(data);input.resize(input_length,0);
        let input_region=D3D11_BOX{left:0,top:0,front:0,right:input_length as u32,bottom:1,back:1};
        (*self.context).UpdateSubresource(self.input as *mut _,0,&input_region,input.as_ptr()as *const c_void,0,0);
        let mut bytes=Vec::new();let mut meta=Vec::<u32>::with_capacity(patterns.len()*2);
        for pattern in patterns{meta.push(bytes.len()as u32);meta.push(pattern.len()as u32);bytes.extend_from_slice(pattern);}
        let bytes_length=(bytes.len()+3)&!3;bytes.resize(bytes_length,0);
        let bytes_region=D3D11_BOX{left:0,top:0,front:0,right:bytes_length as u32,bottom:1,back:1};
        let meta_region=D3D11_BOX{left:0,top:0,front:0,right:(meta.len()*4)as u32,bottom:1,back:1};
        (*self.context).UpdateSubresource(self.pattern_bytes as *mut _,0,&bytes_region,bytes.as_ptr()as *const c_void,0,0);
        (*self.context).UpdateSubresource(self.pattern_meta as *mut _,0,&meta_region,meta.as_ptr()as *const c_void,0,0);
        let groups=((data.len()+255)/256).min(256).max(1)as u32;let parameters=[data.len()as u32,patterns.len()as u32,groups*256,0];
        (*self.context).UpdateSubresource(self.pattern_parameters as *mut _,0,null_mut(),parameters.as_ptr()as *const c_void,0,0);
        (*self.context).ClearUnorderedAccessViewUint(self.pattern_uav,&[0,0,0,0]);
        (*self.context).CSSetShader(self.pattern_shader,null_mut(),0);
        (*self.context).CSSetConstantBuffers(0,1,&self.pattern_parameters);
        let views=[self.srv,self.pattern_srv,self.pattern_meta_srv];(*self.context).CSSetShaderResources(0,3,views.as_ptr());
        (*self.context).CSSetUnorderedAccessViews(0,1,&self.pattern_uav,null_mut());(*self.context).Dispatch(groups,1,1);
        let null_views=[null_mut();3];let null_uav:*mut ID3D11UnorderedAccessView=null_mut();(*self.context).CSSetShaderResources(0,3,null_views.as_ptr());(*self.context).CSSetUnorderedAccessViews(0,1,&null_uav,null_mut());
        (*self.context).CopyResource(self.pattern_staging as *mut _,self.pattern_hits_buffer as *mut _);
        let mut mapped:D3D11_MAPPED_SUBRESOURCE=std::mem::zeroed();let result=(*self.context).Map(self.pattern_staging as *mut _,0,D3D11_MAP_READ,0,&mut mapped);if !SUCCEEDED(result){bail!("GPU 模式结果回读失败：0x{:08X}",result as u32);}
        let source=std::slice::from_raw_parts(mapped.pData as *const u32,patterns.len());let hits=source.iter().map(|value|*value!=0).collect();(*self.context).Unmap(self.pattern_staging as *mut _,0);Ok(hits)
    }

}

impl Drop for GpuEntropy {
    fn drop(&mut self) {
        unsafe {
            if !self.pattern_uav.is_null(){(*self.pattern_uav).Release();}
            if !self.histogram_uav.is_null(){(*self.histogram_uav).Release();}if !self.histogram_parameters.is_null(){(*self.histogram_parameters).Release();}if !self.histogram_staging.is_null(){(*self.histogram_staging).Release();}if !self.histogram_buffer.is_null(){(*self.histogram_buffer).Release();}
            if !self.pattern_meta_srv.is_null(){(*self.pattern_meta_srv).Release();}
            if !self.pattern_srv.is_null(){(*self.pattern_srv).Release();}
            if !self.pattern_parameters.is_null(){(*self.pattern_parameters).Release();}
            if !self.pattern_staging.is_null(){(*self.pattern_staging).Release();}
            if !self.pattern_hits_buffer.is_null(){(*self.pattern_hits_buffer).Release();}
            if !self.pattern_meta.is_null(){(*self.pattern_meta).Release();}
            if !self.pattern_bytes.is_null(){(*self.pattern_bytes).Release();}
            if !self.srv.is_null() { (*self.srv).Release(); }
            if !self.input.is_null() { (*self.input).Release(); }
            if !self.pattern_shader.is_null(){(*self.pattern_shader).Release();}
            if !self.entropy_shader.is_null(){(*self.entropy_shader).Release();}
            if !self.context.is_null() { (*self.context).Release(); }
            if !self.device.is_null() { (*self.device).Release(); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_pattern_matches_cpu_when_hardware_is_available(){
        if crate::settings::load().gpu=="disabled"||!status().contains("已启用"){return;}
        let mut data:Vec<u8>=(0..GPU_MIN_BYTES.max(200_018)).map(|index|(index%251)as u8).collect();let patterns:[&[u8];3]=[b"ValleyRat",b"CreateRemoteThread",b"never-present-pattern"];
        data[1024..1033].copy_from_slice(b"vALLEYrAT");data[200_000..200_018].copy_from_slice(b"CreateRemoteThread");
        assert_eq!(pattern_hits(&data,&patterns),Some(vec![true,true,false]));
    }

    #[test]
    fn gpu_ml_histogram_matches_cpu_when_hardware_is_available(){
        if crate::settings::load().gpu=="disabled"||!status().contains("已启用"){return;}
        let data:Vec<u8>=(0..2*1024*1024+3).map(|i|((i*131+i/7)%256)as u8).collect();
        let Some(chunks)=ml_histograms(&data)else{return;};let mut gpu=[0u32;256];for chunk in chunks[..256*((data.len()+65535)/65536)].chunks_exact(256){for i in 0..256{gpu[i]+=chunk[i];}}let mut cpu=[0u32;256];for byte in &data{cpu[*byte as usize]+=1;}assert_eq!(gpu,cpu);
    }

    #[test]
    #[ignore]
    fn benchmark_16mb_ml_histogram(){
        if !status().contains("已启用"){return;}let data:Vec<u8>=(0usize..16*1024*1024).map(|i|(i.wrapping_mul(131).wrapping_add(i/17)%251)as u8).collect();let _=ml_histograms(&data).expect("GPU warmup");let mut gpu=std::time::Duration::ZERO;let mut cpu=std::time::Duration::ZERO;
        for _ in 0..10{let start=std::time::Instant::now();let _=ml_histograms(&data).unwrap();gpu+=start.elapsed();let start=std::time::Instant::now();let mut sink=0.0;for chunk in data.chunks(65536){let mut counts=[0u32;256];for byte in chunk{counts[*byte as usize]+=1;}let n=chunk.len()as f64;for count in counts{if count>0{let p=count as f64/n;sink-=p*p.log2();}}}std::hint::black_box(sink);cpu+=start.elapsed();}
        println!("16 MiB ML histogram+chunk-entropy input average: DX11={:?}, CPU={:?}, speedup={:.2}x",gpu/10,cpu/10,cpu.as_secs_f64()/gpu.as_secs_f64());
    }

    #[test]
    #[ignore]
    fn benchmark_16mb_pattern_path(){
        if !status().contains("已启用"){return;}
        let data:Vec<u8>=(0..16*1024*1024).map(|index|((index*131+index/17)%251)as u8).collect();
        let patterns:[&[u8];11]=[b"ValleyRat",b"GetVolumeInformationW",b"WinHttpOpen",b"RegSetValueExW",b"VirtualAllocEx",b"WriteProcessMemory",b"CreateRemoteThread",b"schtasks.exe",b"/create",b"powershell",b"-enc"];
        let _=pattern_hits(&data,&patterns).expect("GPU warmup");let mut gpu_elapsed=std::time::Duration::ZERO;let mut cpu_elapsed=std::time::Duration::ZERO;
        for _ in 0..5{let start=std::time::Instant::now();let _=pattern_hits(&data,&patterns).expect("GPU benchmark");gpu_elapsed+=start.elapsed();let start=std::time::Instant::now();let _:Vec<bool>=patterns.iter().map(|pattern|data.windows(pattern.len()).any(|window|window.eq_ignore_ascii_case(pattern))).collect();cpu_elapsed+=start.elapsed();}
        println!("16 MiB / 11 patterns average: DX11={:?}, CPU={:?}",gpu_elapsed/5,cpu_elapsed/5);
    }
}
