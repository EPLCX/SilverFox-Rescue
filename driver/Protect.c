#include <ntddk.h>
#include <wdmsec.h>
#include "Protect.h"

static PVOID gRegistration;
static PEPROCESS gProtectedProcess;
static EX_PUSH_LOCK gStateLock;
static const GUID GUID_DEVCLASS_SFPROTECT = {0x65364e52,0x1bee,0x4ae5,{0x9d,0x90,0xda,0x0b,0x82,0x1c,0x31,0x11}};

static OB_PREOP_CALLBACK_STATUS SfPreOperation(PVOID context, POB_PRE_OPERATION_INFORMATION info)
{
    UNREFERENCED_PARAMETER(context);
    if (info->KernelHandle || info->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;
    ExAcquirePushLockShared(&gStateLock);
    if (gProtectedProcess != NULL && info->Object == gProtectedProcess && PsGetCurrentProcess() != gProtectedProcess) {
        ACCESS_MASK denied = SF_PROCESS_TERMINATE | SF_PROCESS_CREATE_THREAD | SF_PROCESS_VM_OPERATION |
                             SF_PROCESS_VM_WRITE | SF_PROCESS_DUP_HANDLE | SF_PROCESS_SUSPEND_RESUME;
        if (info->Operation == OB_OPERATION_HANDLE_CREATE)
            info->Parameters->CreateHandleInformation.DesiredAccess &= ~denied;
        else if (info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~denied;
    }
    ExReleasePushLockShared(&gStateLock);
    return OB_PREOP_SUCCESS;
}

static VOID SfClearProtectedProcess(VOID)
{
    PEPROCESS old = NULL;
    ExAcquirePushLockExclusive(&gStateLock);
    old = gProtectedProcess; gProtectedProcess = NULL;
    ExReleasePushLockExclusive(&gStateLock);
    if (old != NULL) ObDereferenceObject(old);
}

static NTSTATUS SfDeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SF_PROTECT_CALLER) {
        PEPROCESS next = NULL;
        status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &next);
        if (NT_SUCCESS(status)) {
            SfClearProtectedProcess();
            ExAcquirePushLockExclusive(&gStateLock); gProtectedProcess = next; ExReleasePushLockExclusive(&gStateLock);
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SF_CLEAR_PROTECTION) {
        SfClearProtectedProcess(); status = STATUS_SUCCESS;
    }
    irp->IoStatus.Status = status; irp->IoStatus.Information = 0; IoCompleteRequest(irp, IO_NO_INCREMENT); return status;
}

static NTSTATUS SfCreateClose(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device); irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return STATUS_SUCCESS;
}

static VOID SfUnload(PDRIVER_OBJECT driver)
{
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\Protect");
    SfClearProtectedProcess(); if (gRegistration) ObUnRegisterCallbacks(gRegistration);
    IoDeleteSymbolicLink(&link); if (driver->DeviceObject) IoDeleteDevice(driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Protect");
    UNICODE_STRING linkName = RTL_CONSTANT_STRING(L"\\DosDevices\\Protect");
    // The IOCTL can protect only its own caller, so elevated administrators may
    // register the signed rescue UI without gaining an arbitrary-PID primitive.
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT device = NULL; ExInitializePushLock(&gStateLock);
    NTSTATUS status = IoCreateDeviceSecure(driver, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, (LPCGUID)&GUID_DEVCLASS_SFPROTECT, &device);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&linkName, &deviceName); if (!NT_SUCCESS(status)) { IoDeleteDevice(device); return status; }
    driver->MajorFunction[IRP_MJ_CREATE] = SfCreateClose; driver->MajorFunction[IRP_MJ_CLOSE] = SfCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SfDeviceControl; driver->DriverUnload = SfUnload;
    OB_OPERATION_REGISTRATION operation = {0}; operation.ObjectType = PsProcessType; operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE; operation.PreOperation = SfPreOperation;
    OB_CALLBACK_REGISTRATION registration = {0}; UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385220"); registration.Version = OB_FLT_REGISTRATION_VERSION; registration.OperationRegistrationCount = 1; registration.Altitude = altitude; registration.OperationRegistration = &operation;
    status = ObRegisterCallbacks(&registration, &gRegistration);
    if (!NT_SUCCESS(status)) { IoDeleteSymbolicLink(&linkName); IoDeleteDevice(device); }
    return status;
}
