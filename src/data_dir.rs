//! Machine-wide data root `%ProgramData%\SilverFoxRescue`, restricted to SYSTEM and Administrators.
//!
//! ProgramData lets standard users create subdirectories and own what they create. An
//! unprotected root would let them pre-create or swap the engine DLL, staged updates and
//! quarantine records that this elevated process later loads, runs or restores.
use anyhow::{Context,Result};
use std::{ffi::OsStr,fs::{self,File},os::windows::{ffi::OsStrExt,io::{AsRawHandle,FromRawHandle}},path::{Path,PathBuf},ptr::{null,null_mut},sync::{Mutex,OnceLock}};
use windows_sys::Win32::{Foundation::{LocalFree,HANDLE,INVALID_HANDLE_VALUE},Security::{CreateWellKnownSid,EqualSid,GetSecurityDescriptorDacl,GetSecurityDescriptorOwner,WinLocalSystemSid,ACL,PSECURITY_DESCRIPTOR,PSID,SECURITY_ATTRIBUTES,DACL_SECURITY_INFORMATION,OWNER_SECURITY_INFORMATION,PROTECTED_DACL_SECURITY_INFORMATION,Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW,GetSecurityInfo,SetSecurityInfo,SDDL_REVISION_1,SE_FILE_OBJECT}},Storage::FileSystem::*,System::Com::CoTaskMemFree,UI::Shell::{SHGetKnownFolderPath,FOLDERID_ProgramData}};

/// Owner Administrators; full control for SYSTEM and Administrators only, inherited by children.
pub(crate) const DIRECTORY_SDDL:&str="O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// The same access for a single file, without inheritance flags.
pub(crate) const FILE_SDDL:&str="O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const MAX_DEPTH:usize=32;

fn wide(value:&OsStr)->Vec<u16>{value.encode_wide().chain(Some(0)).collect()}
fn handle(file:&File)->HANDLE{file.as_raw_handle() as HANDLE}

pub(crate) struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor{
    pub(crate) fn from_sddl(sddl:&str)->Result<Self>{
        let mut descriptor=null_mut();
        if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(OsStr::new(sddl)).as_ptr(),SDDL_REVISION_1,&mut descriptor,null_mut())}==0{return Err(std::io::Error::last_os_error()).context("创建安全描述符失败");}
        Ok(Self(descriptor))
    }
    fn parts(&self)->Result<(PSID,*mut ACL)>{
        let(mut present,mut defaulted,mut dacl,mut owner)=(0,0,null_mut(),null_mut());
        if unsafe{GetSecurityDescriptorDacl(self.0,&mut present,&mut dacl,&mut defaulted)==0||present==0||dacl.is_null()||GetSecurityDescriptorOwner(self.0,&mut owner,&mut defaulted)==0||owner.is_null()}{anyhow::bail!("读取安全描述符失败");}
        Ok((owner,dacl))
    }
    /// Replaces the owner and the DACL (protected from inheritance) of an open handle.
    pub(crate) fn apply(&self,handle:HANDLE)->Result<()>{
        let(owner,dacl)=self.parts()?;
        let status=unsafe{SetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,owner,null_mut(),dacl,null())};
        if status!=0{anyhow::bail!("设置权限失败：Windows 错误 {status}");}
        Ok(())
    }
}
impl Drop for Descriptor{fn drop(&mut self){unsafe{LocalFree(self.0);}}}

/// Opens a file or directory for security changes without following reparse points.
pub(crate) fn open_for_security(path:&Path,access:u32,share:u32)->std::io::Result<File>{
    let handle=unsafe{CreateFileW(wide(path.as_os_str()).as_ptr(),FILE_READ_ATTRIBUTES|READ_CONTROL|WRITE_DAC|WRITE_OWNER|access,share,null(),OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,null_mut())};
    if handle==INVALID_HANDLE_VALUE{return Err(std::io::Error::last_os_error());}
    Ok(unsafe{File::from_raw_handle(handle as _)})
}

pub(crate) fn information(file:&File)->Result<BY_HANDLE_FILE_INFORMATION>{
    let mut info:BY_HANDLE_FILE_INFORMATION=unsafe{std::mem::zeroed()};
    if unsafe{GetFileInformationByHandle(handle(file),&mut info)}==0{return Err(std::io::Error::last_os_error()).context("读取文件信息失败");}
    Ok(info)
}

fn owner_is_trusted(file:&File,administrators:PSID)->Result<bool>{
    let(mut owner,mut descriptor)=(null_mut(),null_mut());
    let status=unsafe{GetSecurityInfo(handle(file),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,&mut owner,null_mut(),null_mut(),null_mut(),&mut descriptor)};
    if status!=0{anyhow::bail!("读取所有者失败：Windows 错误 {status}");}
    let mut system=[0u32;17];let mut length=std::mem::size_of_val(&system)as u32;
    let trusted=unsafe{!owner.is_null()&&(EqualSid(owner,administrators)!=0
        ||(CreateWellKnownSid(WinLocalSystemSid,null_mut(),system.as_mut_ptr().cast(),&mut length)!=0&&EqualSid(owner,system.as_mut_ptr().cast())!=0))};
    unsafe{LocalFree(descriptor);}
    Ok(trusted)
}

pub(crate) fn program_data()->Result<PathBuf>{
    unsafe{
        let mut path=null_mut();
        let result=SHGetKnownFolderPath(&FOLDERID_ProgramData,0,null_mut(),&mut path);
        if result<0{anyhow::bail!("获取 ProgramData 目录失败：{result:#x}");}
        let mut len=0;while *path.add(len)!=0{len+=1;}
        let value=PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(path,len)));
        CoTaskMemFree(path.cast());Ok(value)
    }
}

/// Creates `path` if missing, refuses reparse points and directories owned by anyone other
/// than Administrators or SYSTEM, then applies `DIRECTORY_SDDL`. The returned handle omits
/// FILE_SHARE_DELETE, so the directory cannot be renamed or replaced while it is held.
pub(crate) fn protect_directory(path:&Path)->Result<File>{
    let descriptor=Descriptor::from_sddl(DIRECTORY_SDDL)?;
    let security=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>()as u32,lpSecurityDescriptor:descriptor.0,bInheritHandle:0};
    if unsafe{CreateDirectoryW(wide(path.as_os_str()).as_ptr(),&security)}==0{
        let error=std::io::Error::last_os_error();
        if error.raw_os_error()!=Some(183){return Err(error).with_context(||format!("创建目录 {} 失败",path.display()));}
    }
    let directory=open_for_security(path,0,FILE_SHARE_READ|FILE_SHARE_WRITE).with_context(||format!("打开目录 {} 失败",path.display()))?;
    let info=information(&directory)?;
    if info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT!=0||info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY==0{anyhow::bail!("{} 含重解析点或不是目录",path.display());}
    let(administrators,_)=descriptor.parts()?;
    if !owner_is_trusted(&directory,administrators)?{anyhow::bail!("{} 的所有者不是管理员或 SYSTEM",path.display());}
    descriptor.apply(handle(&directory)).with_context(||format!("设置目录 {} 的权限失败",path.display()))?;
    Ok(directory)
}

/// The data root path, for path comparisons only. Use `secure` before touching its contents.
pub fn path()->&'static Path{
    static PATH:OnceLock<PathBuf>=OnceLock::new();
    PATH.get_or_init(||program_data()
        .or_else(|_|std::env::var_os("PROGRAMDATA").map(PathBuf::from).context("缺少 ProgramData"))
        .unwrap_or_else(|_|std::env::temp_dir())
        .join("SilverFoxRescue"))
}

static ROOT_HANDLE:Mutex<Option<File>>=Mutex::new(None);

/// Returns the data root after restricting it and everything below it to SYSTEM and
/// Administrators. The first successful call per process walks the tree; objects owned by
/// anyone else and reparse points are removed, because they can only have been planted.
/// Call this before creating, loading, running or trusting anything stored under the root.
pub fn secure()->Result<&'static Path>{
    let mut held=ROOT_HANDLE.lock().unwrap_or_else(|error|error.into_inner());
    let root=path();
    if held.is_some(){return Ok(root);}
    let directory=protect_directory(root).context("数据目录权限加固失败")?;
    let directories=Descriptor::from_sddl(DIRECTORY_SDDL)?;let files=Descriptor::from_sddl(FILE_SDDL)?;
    let(administrators,_)=directories.parts()?;
    let removed=secure_children(root,&directories,&files,administrators,0).context("数据目录权限加固失败")?;
    if removed>0{crate::audit::record("data_root",&format!("已清除数据目录中 {removed} 个非管理员创建的对象或重解析点"));}
    *held=Some(directory);
    Ok(root)
}

fn secure_children(directory:&Path,directories:&Descriptor,files:&Descriptor,administrators:PSID,depth:usize)->Result<usize>{
    if depth>=MAX_DEPTH{anyhow::bail!("目录层级过深：{}",directory.display());}
    let mut removed=0;
    for entry in fs::read_dir(directory).with_context(||format!("读取目录 {} 失败",directory.display()))?{
        let path=entry?.path();
        let object=match open_for_security(&path,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE){
            Ok(object)=>object,
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>continue,
            Err(error)=>return Err(error).with_context(||format!("打开 {} 失败",path.display())),
        };
        let info=information(&object)?;
        let is_directory=info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY!=0;
        let reparse=info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT!=0;
        if reparse||!owner_is_trusted(&object,administrators)?{
            drop(object);
            // Links are removed without following them; planted trees are removed whole.
            let result=match(reparse,is_directory){(true,true)=>fs::remove_dir(&path),(_,false)=>fs::remove_file(&path),(false,true)=>fs::remove_dir_all(&path)};
            result.with_context(||format!("无法清除非管理员创建的对象 {}",path.display()))?;
            removed+=1;continue;
        }
        let descriptor=if is_directory{directories}else{files};
        descriptor.apply(handle(&object)).with_context(||format!("设置 {} 的权限失败",path.display()))?;
        drop(object);
        if is_directory{removed+=secure_children(&path,directories,files,administrators,depth+1)?;}
    }
    Ok(removed)
}

#[cfg(test)]
pub(crate) mod tests{
    use super::*;
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;

    /// Owner and DACL of `path` as SDDL, without following reparse points.
    pub(crate) fn sddl_of(path:&Path)->String{
        let file=open_for_security(path,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE).unwrap();
        let mut descriptor=null_mut();
        let status=unsafe{GetSecurityInfo(handle(&file),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,null_mut(),null_mut(),null_mut(),null_mut(),&mut descriptor)};
        assert_eq!(status,0);
        let(mut text,mut length)=(null_mut(),0);
        assert_ne!(unsafe{ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,SDDL_REVISION_1,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut text,&mut length)},0);
        let value=String::from_utf16_lossy(unsafe{std::slice::from_raw_parts(text,length as usize)}).trim_end_matches('\0').to_owned();
        unsafe{LocalFree(text.cast());LocalFree(descriptor);}
        value
    }

    pub(crate) fn junction(link:&Path,target:&Path){
        let status=std::process::Command::new("cmd").args(["/c","mklink","/J"]).arg(link).arg(target).output().unwrap();
        assert!(status.status.success(),"mklink /J 失败：{}",String::from_utf8_lossy(&status.stderr));
    }

    #[test] #[ignore="需要管理员权限，修改临时目录的所有者和 DACL"]
    fn protected_tree_removes_links_and_restricts_children(){
        let base=std::env::temp_dir().join(format!("silverfox-data-dir-{}",std::process::id()));
        let root=base.join("root");let outside=base.join("outside");
        fs::create_dir_all(root.join("nested")).unwrap();fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("nested").join("record.json"),b"{}").unwrap();fs::write(outside.join("keep.txt"),b"keep").unwrap();
        let outside_before=sddl_of(&outside.join("keep.txt"));
        junction(&root.join("link"),&outside);

        let _held=protect_directory(&root).unwrap();
        let directories=Descriptor::from_sddl(DIRECTORY_SDDL).unwrap();let files=Descriptor::from_sddl(FILE_SDDL).unwrap();
        let(administrators,_)=directories.parts().unwrap();
        assert_eq!(secure_children(&root,&directories,&files,administrators,0).unwrap(),1);

        assert!(!root.join("link").exists());
        assert_eq!(fs::read(outside.join("keep.txt")).unwrap(),b"keep");
        assert_eq!(sddl_of(&outside.join("keep.txt")),outside_before);
        assert_eq!(sddl_of(&root),"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert_eq!(sddl_of(&root.join("nested")),"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert_eq!(sddl_of(&root.join("nested").join("record.json")),"O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)");
        drop(_held);fs::remove_dir_all(&base).unwrap();
    }
}