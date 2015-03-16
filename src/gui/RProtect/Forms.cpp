#include "Common.h"
#include "Forms.h"
#include "RProtect.h"
#include "QueryStatus.h"
#include "EventHandler.h"


HWND g_hMain = NULL;


HANDLE g_hEvtUIReady;

BOOL MainDlgPageOnInit (HWND hwnd, HWND hwndFocus, LPARAM lParam) {
	if (IsMonOn(CRIME_MAJOR_PROC))
		CheckDlgButton(hwnd, IDC_START_PROC_MON, BST_CHECKED);

	if (IsMonOn(CRIME_MAJOR_FILE))
		CheckDlgButton(hwnd, IDC_START_FILE_MON, BST_CHECKED);

	if (IsMonOn(CRIME_MAJOR_REG))
		CheckDlgButton(hwnd, IDC_START_REG_MON, BST_CHECKED);

	if (IsMonOn(CRIME_MAJOR_SYS))
		CheckDlgButton(hwnd, IDC_START_SYS_MON, BST_CHECKED);

	SetEvent(g_hEvtUIReady);
	return TRUE;
}





VOID MainDlgOnCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify) {
	switch (id) {
		case IDC_START_PROC_MON:
			if (IsDlgButtonChecked(hwnd, id) == BST_CHECKED)
				SetMon(CRIME_MAJOR_PROC, TRUE);
			else if (IsDlgButtonChecked(hwnd, id) == BST_UNCHECKED)
				SetMon(CRIME_MAJOR_PROC, FALSE);
			break;
		case IDC_START_FILE_MON:
			if (IsDlgButtonChecked(hwnd, id) == BST_CHECKED)
				SetMon(CRIME_MAJOR_FILE, TRUE);
			else if (IsDlgButtonChecked(hwnd, id) == BST_UNCHECKED)
				SetMon(CRIME_MAJOR_FILE, FALSE);
			break;
		case IDC_START_REG_MON:
			if (IsDlgButtonChecked(hwnd, id) == BST_CHECKED)
				SetMon(CRIME_MAJOR_REG, TRUE);
			else if (IsDlgButtonChecked(hwnd, id) == BST_UNCHECKED)
				SetMon(CRIME_MAJOR_REG, FALSE);
			break;
		case IDC_START_SYS_MON:
			if (IsDlgButtonChecked(hwnd, id) == BST_CHECKED)
				SetMon(CRIME_MAJOR_SYS, TRUE);
			else if (IsDlgButtonChecked(hwnd, id) == BST_UNCHECKED)
				SetMon(CRIME_MAJOR_SYS, FALSE);
			break;
	}
}


INT_PTR WINAPI MainDlg_Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {

		HANDLE_DLGMSG(hwnd, WM_INITDIALOG, MainDlgPageOnInit);
		HANDLE_DLGMSG(hwnd, WM_COMMAND, MainDlgOnCommand);

		case WM_CLOSE:
			if (IDYES == MessageBox(hwnd, TEXT("是否确定退出？"), TEXT("RProtect"), MB_YESNO))
				EndDialog(hwnd, FALSE);

			return FALSE;
			break;

		default:
			return FALSE;
			break;
	}
}



INT_PTR WINAPI EventDlg_Proc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_INITDIALOG:
			{
				RECT rcScreen, rcSelf;
				SystemParametersInfo(SPI_GETWORKAREA, 0, &rcScreen, 0);
				GetWindowRect(hwnd, &rcSelf);
				int nSelfWidth = rcSelf.right - rcSelf.left;
				int nSelfHeight = rcSelf.bottom - rcSelf.top;

				SetWindowPos(hwnd, HWND_TOPMOST, rcScreen.right - nSelfWidth, rcScreen.bottom - nSelfHeight, 0, 0, SWP_NOSIZE);

				SetDlgItemText(hwnd, IDC_CRIMINAL, g_UsrEvtData.wzCriminal);
				SetDlgItemText(hwnd, IDC_VICTIM, g_UsrEvtData.wzVictim);

				TCHAR tzMsg[512] = TEXT("znmdsmqk");
				GetDetail(g_UsrEvtData.ulCrimeType, tzMsg, 512);
				SetDlgItemText(hwnd, IDC_DETAIL, tzMsg);

				return TRUE;
			}
			break;
		case WM_COMMAND:
			{
				if (LOWORD(wParam) == IDC_ACCEPT && HIWORD(wParam) == BN_CLICKED) {
					ULONG ulResult = JUDGMENT_ACCEPT;
					if ( BST_CHECKED == IsDlgButtonChecked(hwnd, IDC_ALWAYS) )
						ulResult |= JUDGMENT_ALWAYS;
					EndDialog(hwnd, ulResult);
				}
				else if (LOWORD(wParam) == IDC_REFUSE && HIWORD(wParam) == BN_CLICKED) {
					ULONG ulResult = JUDGMENT_REFUSE;
					if ( BST_CHECKED == IsDlgButtonChecked(hwnd, IDC_ALWAYS) )
						ulResult |= JUDGMENT_ALWAYS;
					EndDialog(hwnd, ulResult);
				}

				return FALSE;
			}
			break;
		default:
			{
				return FALSE;
			}
			break;
	}
}