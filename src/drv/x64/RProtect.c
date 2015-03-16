/*++

Module Name:

	RProtect.c - 驱动入口模块


Abstract:

	该模块是驱动入口点，负责加载、卸载，以及各IRP派遣历程的处理。


Author:

	Fypher

	2012/02/27

--*/
#include <ntddk.h>
#include "Common.h"
#include "RProtect.h"
#include "Hook.h"
#include "FkMS.h"
#include "SysCallFlt.h"
#include "EventHandler.h"
#include "WhiteBlackList.h"

BOOLEAN g_bReady = FALSE;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING usDevName, usSymLinkName;
	PDEVICE_OBJECT pDevObj;
	NTSTATUS status;

	KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Hello Matrix!\r\n"));

#ifdef RP_DBG
	DriverObject->DriverUnload = DriverExit;
#else
	DriverObject->DriverUnload = NULL;
#endif

	RtlInitUnicodeString(&usDevName, L"\\Device\\"DRV_NAME);
	status = IoCreateDevice(DriverObject, 0, &usDevName, FILE_DEVICE_UNKNOWN,
							FILE_DEVICE_SECURE_OPEN, TRUE, &pDevObj);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlInitUnicodeString(&usSymLinkName, L"\\DosDevices\\"DRV_NAME);
	status = IoCreateSymbolicLink(&usSymLinkName, &usDevName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pDevObj);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MyCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = MyCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDeviceControl;

	if (!StartWork()) {
		IoDeleteSymbolicLink(&usSymLinkName);
		IoDeleteDevice(pDevObj);
		return STATUS_UNSUCCESSFUL;
	}

	g_bReady = TRUE;

	return STATUS_SUCCESS;
}


VOID DriverExit(IN PDRIVER_OBJECT DriverObject) {

	UNICODE_STRING usSymLinkName;
	ULONG_PTR ulpNewVirtualAddr;
	PAGED_CODE();

	KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Bye Matrix!\r\n"));

	RtlInitUnicodeString(&usSymLinkName, L"\\DosDevices\\"DRV_NAME);
	IoDeleteSymbolicLink(&usSymLinkName);

	IoDeleteDevice(DriverObject->DeviceObject);

	// unhook
	Hook(g_ulpHookPoint, g_Signature, sizeof(g_Signature));

	CancelAllEvents();

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	while (!IsAllHookObjectNotInUse())
	{
		LARGE_INTEGER interval;
		interval.QuadPart = -2LL * 1000LL * 1000LL * 10LL;
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	ExDeleteNPagedLookasideList(&g_EventDataPageList);

	EraseWhiteBlackHashTable();

}


// IRP_MJ_CREATE
NTSTATUS MyCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PAGED_CODE();
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;

	if (g_bReady && IsCurrentProcRProcess()) {
		PEPROCESS pCurEproc = PsGetCurrentProcess();
		if (pCurEproc) {
			PUNICODE_STRING pusCurProcName = GetProcNameByEproc(pCurEproc);
			if (pusCurProcName) {
				AddToWhiteBlackHashTable(pusCurProcName, CRIME_MAJOR_ALL, NODE_TYPE_WHITE);
				ExFreePool(pusCurProcName);

				CancelAllEvents();

				g_pProtected = pCurEproc;

				KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "MyCreate\r\n"));
				Irp->IoStatus.Status = STATUS_SUCCESS;

			}
		}
	}

	IoCompleteRequest (Irp,IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

// IRP_MJ_CLOSE、IRP_MJ_CLEANUP
NTSTATUS MyCloseCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PAGED_CODE();
	Irp->IoStatus.Information = 0;
	g_pProtected = NULL;
	KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "MyCloseCleanup\r\n"));
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest (Irp,IO_NO_INCREMENT);

	CancelAllEvents();

	return Irp->IoStatus.Status;
}


// IRP_MJ_DEVICE_CONTROL
NTSTATUS MyDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
	ULONG code = irpsp->Parameters.DeviceIoControl.IoControlCode;
	ULONG inlen = irpsp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outlen = irpsp->Parameters.DeviceIoControl.OutputBufferLength;

	PAGED_CODE();

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;

	switch (code) {
		case IOCTL_GET_EVENT:
			if (outlen == sizeof(USEREVENTDATA)) {
				PEVENTDATA pEvtData;
				LARGE_INTEGER interval;

				interval.QuadPart = -3LL * 1000LL * 1000LL * 10LL;	//
				pEvtData = PopEvent(&interval);

				if (pEvtData) {
					BuildUserEventData(pEvtData, (PUSEREVENTDATA)Irp->AssociatedIrp.SystemBuffer);
					Irp->IoStatus.Information = sizeof(USEREVENTDATA);
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
			}
			break;
		case IOCTL_GIVE_JUDGMENT:
			if (inlen == sizeof(JUDGMENTDATA)) {
				PJUDGMENTDATA pJudgData = (PJUDGMENTDATA)Irp->AssociatedIrp.SystemBuffer;
				PEVENTDATA pEvtData = (PEVENTDATA)pJudgData->ulpEvtData;
				__try {
					MyProbeForRead(pEvtData, sizeof(EVENTDATA), 1, MEM_TYPE_KERNELMODE);
					pEvtData->ulJudgment = pJudgData->ulJudgment;
					KeSetEvent(&pEvtData->evt, IO_NO_INCREMENT, FALSE);
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}__except (EXCEPTION_EXECUTE_HANDLER)
				{
					KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "MyDeviceControl failed!\r\n"));
				}
			}
			break;

		case IOCTL_GET_MAJOR_PROTECTED_INFO:
			if (inlen == sizeof(USER_MAJOR_PROTECTED_INFO) && outlen == sizeof(USER_MAJOR_PROTECTED_INFO)) {
				PUSER_MAJOR_PROTECTED_INFO pUsrMjProInfo = (PUSER_MAJOR_PROTECTED_INFO)Irp->AssociatedIrp.SystemBuffer;
				__try {
					MyProbeForRead(pUsrMjProInfo, sizeof(USER_MAJOR_PROTECTED_INFO), 1, MEM_TYPE_KERNELMODE);
					pUsrMjProInfo->ulIsProtected = (ULONG)IsMajorProtected(pUsrMjProInfo->ulCrimeType);
					Irp->IoStatus.Information = sizeof(USER_MAJOR_PROTECTED_INFO);
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}__except (EXCEPTION_EXECUTE_HANDLER)
				{
					KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "MyDeviceControl failed!\r\n"));
				}
			}
			break;

		case IOCTL_SET_MAJOR_PROTECTED:
			if (inlen == sizeof(USER_MAJOR_PROTECTED_INFO)) {
				PUSER_MAJOR_PROTECTED_INFO pUsrMjProInfo = (PUSER_MAJOR_PROTECTED_INFO)Irp->AssociatedIrp.SystemBuffer;
				__try {
					MyProbeForRead(pUsrMjProInfo, sizeof(USER_MAJOR_PROTECTED_INFO), 1, MEM_TYPE_KERNELMODE);
					SetMajorProtectedType(pUsrMjProInfo->ulCrimeType, (BOOLEAN)pUsrMjProInfo->ulIsProtected);
					pUsrMjProInfo->ulIsProtected = (ULONG)IsMajorProtected(pUsrMjProInfo->ulCrimeType);
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}__except (EXCEPTION_EXECUTE_HANDLER)
				{
					KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "MyDeviceControl failed!\r\n"));
				}
			}
			break;
	}


	IoCompleteRequest (Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}


BOOLEAN StartWork()
{
	PAGED_CODE();
	// not working in safe mode!
	if (*InitSafeBootMode)
		return FALSE;

	g_ulOsVersion = GetOsVersion();
	if (g_ulOsVersion != OS_VERSION_ERROR)		// only tested on win7
	{
		if (!InitCommonVars())
			return FALSE;

		if (!InitShadowServiceId())
			return FALSE;

		if (!InitFakeSysCallTable())
			return FALSE;

		return Hook(g_ulpHookPoint, g_HookCodes, sizeof(g_HookCodes));
	}

	return FALSE;
}
