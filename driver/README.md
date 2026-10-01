# 保护驱动

SilverFoxProtect 使用对象回调保护登记进程的句柄访问。设备 DACL 允许管理员和 LocalSystem 打开设备，登记操作将调用者自身的进程对象设为保护目标。外部句柄的终止、创建线程、写内存、复制句柄和挂起权限会被削减。

`IOCTL_SF_CLEAR_PROTECTION` 解除登记；驱动卸载时释放进程引用、对象回调、设备及符号链接。客户端正常关闭流程执行解除保护和停止服务，设置页面显示实际服务与登记状态。

使用已安装的 WDK 和 `SilverFoxProtect.vcxproj` 构建。项目根目录执行 `build.ps1 --build-dll` 可生成 SYS、INF 和 CAT；常规客户端构建复用驱动包。正式部署按目标 Windows 平台要求完成驱动签名，构建与发布时核验对象回调 Altitude 的分配情况。

脚本从 `CARGO_TARGET_DIR` 动态读取 D 盘目标目录，驱动编译中间文件和未签名包保存在 `<CARGO_TARGET_DIR>\silverfox-driver`。直接通过 Visual Studio 项目构建时，项目文件也使用进程中的 `CARGO_TARGET_DIR` 设置输出目录。主构建脚本从该目录读取驱动包，并将发布文件复制到 `dist/driver`。
