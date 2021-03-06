
// SYNScannerDlg.h : header file
//

#pragma once


// CSYNScannerDlg dialog
class CSYNScannerDlg : public CDialogEx
{
// Construction
public:
	CSYNScannerDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SYNSCANNER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	// local ip
	CString m_cstrMyIP;
	CIPAddressCtrl m_ipaddrDst;
	CIPAddressCtrl m_ipaddrSrc;
	CEdit m_editDstStartPort;
	CEdit m_editDstEndPort;
	CEdit m_editSrcPort;
	CListCtrl m_clistctrlScanResults;
	CEdit m_editRecvTimeOut;
	SOCKET m_sockRawSend;
	afx_msg void OnClickedButtonScan();
	CString m_cstrWindowsText;
	afx_msg void OnClose();
	CListCtrl m_clistctrlValidPorts;
	HANDLE m_hThreadSend;
	HANDLE m_hThreadRecv;
	CButton m_cbtnScan;
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	SOCKET m_sockRawRecv;
};
