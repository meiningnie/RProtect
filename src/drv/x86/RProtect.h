#ifndef _RPROTECT_H_
#define _RPROTECT_H_


#define IOCTL_GET_EVENT									\
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa01,				\
	METHOD_BUFFERED, FILE_READ_DATA )

#define IOCTL_GIVE_JUDGMENT								\
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa02, 				\
	METHOD_BUFFERED, FILE_WRITE_DATA)


#define IOCTL_GET_MAJOR_PROTECTED_INFO					\
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa03, 				\
	METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SET_MAJOR_PROTECTED						\
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa04, 				\
	METHOD_BUFFERED, FILE_WRITE_DATA)


typedef struct _USER_MAJOR_PROTECTED_INFO_ {
	ULONG ulCrimeType;
	ULONG ulIsProtected;				// not BOOLEAN, sizeof(BOOLEAN) may be different in ring0/ring3
} USER_MAJOR_PROTECTED_INFO, *PUSER_MAJOR_PROTECTED_INFO, *PPUSER_MAJOR_PROTECTED_INFO;

VOID KiFastCallEntry_Detour_BeforeVista();
VOID KiFastCallEntry_Detour_AfterVista();


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);

VOID DriverExit(IN PDRIVER_OBJECT DriverObject);

NTSTATUS MyCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS MyCloseCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS MyDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

BOOLEAN StartWork();

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverExit)
#pragma alloc_text(PAGE, MyCreate)
#pragma alloc_text(PAGE, MyCloseCleanup)
#pragma alloc_text(PAGE, MyDeviceControl)
#pragma alloc_text(INIT, StartWork)
#endif


#endif
