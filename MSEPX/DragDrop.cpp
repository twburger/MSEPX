// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  Based on MSDN Magazine, October 2004 drag and drop code written by Paul DiLascia: Create Client Windows, Drag and Drop Between Listboxes http://msdn.microsoft.com/en-us/magazine/cc163915.aspx
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


#include "stdafx.h"
#include "DragDrop.h"
//#include <afxpriv.h> // for AfxLoadString

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//const UINT WM_DD_DRAGENTER = RegisterWindowMessage(_T("WM_DD_DRAGENTER"));
//const UINT WM_DD_DRAGOVER  = RegisterWindowMessage(_T("WM_DD_DRAGOVER"));
//const UINT WM_DD_DRAGDROP  = RegisterWindowMessage(_T("WM_DD_DRAGDROP"));
//const UINT WM_DD_DRAGABORT = RegisterWindowMessage(_T("WM_DD_DRAGABORT"));

// Macro to get point from WM_ mouse messages
//#define GETPOINT(lp) (CPoint(GET_X_LPARAM(lp), GET_Y_LPARAM(lp)))
//#define GETPOINT(lp) (POINT(GET_X_LPARAM(lp), GET_Y_LPARAM(lp)))

CDragDropMgr::CDragDropMgr()
{
	m_bDrag = FALSE;
	m_pMainWnd = NULL;
	m_hwndTracking = NULL;
	m_hCursorSave = NULL;
	m_pDragImage = NULL;
	m_iState = 0;
	SetCursors(LoadCursor(NULL, IDC_ARROW), LoadCursor(NULL, IDC_NO));
	memset(&m_info,0,sizeof(m_info));
}

CDragDropMgr::~CDragDropMgr()
{
}

BOOL CDragDropMgr::Install(HWND pMainWnd, DRAGDROPWND* ddwnds)
{
	m_pMainWnd = pMainWnd;
	for (int i=0; ddwnds[i].type; i++) {
		HWND hwnd = GetDlgItem(pMainWnd, ddwnds[i].id);
		ASSERT(hwnd && IsWindow(hwnd));
		m_mapHwnd[hwnd] = ddwnds[i].type;
	}

	return TRUE;
}

void CDragDropMgr::AddWindow(HWND hwnd, int type)
{
	m_mapHwnd[hwnd] = type;
}

void CDragDropMgr::RemoveWindow(HWND hwnd)
{
	HWNDMAP::iterator pos = m_mapHwnd.find(hwnd);
	if (pos != m_mapHwnd.end()) {
		m_mapHwnd.erase(pos);
	}
}

UINT CDragDropMgr::GetWindowType(HWND hwnd)
{
	HWNDMAP::const_iterator pos = m_mapHwnd.find(hwnd);
	return pos != m_mapHwnd.end() ? pos->second : 0;
}

//////////////////
// detail: Note that this works for input only
//
BOOL CDragDropMgr::PreTranslateMessage(MSG* pMsg)
{
	const MSG& msg = *pMsg;

	if (msg.hwnd)
	{
		if(IsSourceWnd(msg.hwnd)) {
			if (msg.message==WM_LBUTTONDOWN) {
				return OnLButtonDown(msg);

			} else if (msg.message==WM_MOUSEMOVE) {
				return OnMouseMove(msg);

			} else if (msg.message==WM_LBUTTONUP) {
				return OnLButtonUp(msg);

			} else if (msg.message==WM_KEYDOWN && msg.wParam==VK_ESCAPE) {
				if (m_iState) {
					SendMessage(m_pMainWnd,WM_DD_DRAGABORT, 0, NULL);
					//m_pMainWnd->SendMessage(WM_DD_DRAGABORT, 0, NULL);
					SetState(NONE);
					delete m_info.data;
					m_info.data=NULL;
					return 1;
				}
			}
		}
	}
	return FALSE;
}

// get a point from the LPARAM argument of a windwo message
POINT CDragDropMgr::GetPoint( LPARAM lp )
{
	POINT p;
	p.x = GET_X_LPARAM(lp);
	p.y = GET_Y_LPARAM(lp);

	return p;
}

//////////////////
// Handle button-down message: enter CAPTURED state.
//
BOOL CDragDropMgr::OnLButtonDown(const MSG& msg)
{
	SendMessage(msg.hwnd, msg.message, msg.wParam, msg.lParam);
	m_hwndTracking = msg.hwnd;
	m_ptOrg = CDragDropMgr::GetPoint(msg.lParam);
	//m_ptOrg = GETPOINT(msg.lParam);
	SetState(CAPTURED);
	return TRUE;
}

//////////////////
// Handle mousemove: enter DRAGGING state.
//
int CDragDropMgr::OnMouseMove(const MSG& msg)
{
	if (!m_iState)
		return FALSE;

	HWND pWnd = m_hwndTracking;
	POINT pt = GetPoint(msg.lParam);
	//CWnd* pWnd = CWnd::FromHandle(m_hwndTracking);
	//CPoint pt = GETPOINT(msg.lParam);
	DRAGDROPINFO& dd = m_info;

	if (IsDragging()) {
		// already dragging: move drag image
		ClientToScreen( pWnd, &pt);			 // convert to screen coords
		//pWnd->ClientToScreen(&pt);			 // convert to screen coords
		ImageList_DragMove(pt.x, pt.y);		 // move drag image
		//m_pDragImage->DragMove(pt);		 // move drag image

		// get new target window if any and set cursor appropriately
		ScreenToClient(m_pMainWnd,&pt); // convert to main window coords
		//m_pMainWnd->ScreenToClient(&pt); // convert to main window coords
		dd.pt = pt;
		dd.hwndTarget = ChildWindowFromPoint(m_pMainWnd, pt);
		//dd.hwndTarget = m_pMainWnd->ChildWindowFromPoint(pt)->GetSafeHwnd();
		SendMessage(m_pMainWnd, WM_DD_DRAGOVER, 0, (LPARAM)(void*)&dd);
		//m_pMainWnd->SendMessage(WM_DD_DRAGOVER, 0, (LPARAM)(void*)&dd);
		SetCursor(dd.hwndTarget && IsTargetWnd(dd.hwndTarget) ? m_hCursorDrop : m_hCursorNo);

	} else {
		// Not dragging yet: enter drag mode if mouse moves beyond threshhold.
		POINT delta;
		delta.x = pt.x - m_ptOrg.x;
		delta.y = pt.y - m_ptOrg.y;
		static POINT jog;
		jog.x = GetSystemMetrics(SM_CXDRAG);
		jog.x = GetSystemMetrics(SM_CYDRAG);
		//static CPoint jog();
		//CPoint delta = pt - m_ptOrg;
		//static CPoint jog(GetSystemMetrics(SM_CXDRAG),GetSystemMetrics(SM_CYDRAG));

		if (abs(delta.x)>=jog.x || abs(delta.y)>jog.y) {
			dd.hwndSource = m_hwndTracking;
			dd.pt = m_ptOrg;	// start from ORIGINAL point, not where now
			dd.hwndTarget = NULL;
			dd.data = NULL;

			m_bDrag = FALSE; // reset the flag

			// Send main window a message: enter drag mode. 
			SendMessage(m_pMainWnd, WM_DD_DRAGENTER,
				GetDlgCtrlID(m_hwndTracking), (LPARAM)(void*)&dd);
			
			//BOOL bDrag = (BOOL)m_pMainWnd->SendMessage(WM_DD_DRAGENTER,
			//	::GetDlgCtrlID(m_hwndTracking), (LPARAM)(void*)&dd);

			if (m_bDrag && dd.data) {
				SetState(DRAGGING);			 // I am now dragging
				OnMouseMove(msg);
				
				ClientToScreen(pWnd, &pt);
				RECT rc;
				m_pDragImage = dd.data->CreateDragImage(pWnd, rc);
				ImageList_BeginDrag( m_pDragImage, 0, rc.right, rc.bottom);
				ImageList_DragEnter(NULL, pt.x, pt.y);

				//m_pDragImage = ListView_CreateDragImage( pWnd, 0, &pt );
				//pWnd->ClientToScreen(&pt);
				//CRect rc;
				//m_pDragImage = dd.data->CreateDragImage(pWnd, rc);
				//m_pDragImage->BeginDrag(0, rc.BottomRight());
				//m_pDragImage->DragEnter(NULL,pt);

			} else {
				SetState(NONE);
			}
		}
	}
	return TRUE;
}

//////////////////
// Handle button-up: drop the data and return to home state (NONE).
//
BOOL CDragDropMgr::OnLButtonUp(const MSG& msg)
{
	if (!IsDragging()) {
		SetState(NONE); 
		return FALSE;
	}
	DRAGDROPINFO& dd = m_info;
	if (IsTargetWnd(dd.hwndTarget)) {
		POINT pt = GetPoint(msg.lParam);
		HWND pWndSource = dd.hwndSource;
		HWND pWndTarget = dd.hwndTarget;
		ClientToScreen(pWndSource,&pt);
		ScreenToClient(pWndTarget,&pt);
		dd.pt = pt;
		SendMessage(m_pMainWnd, WM_DD_DRAGDROP, GetDlgCtrlID(pWndTarget), (LPARAM)(void*)&dd);

		//CPoint pt = GETPOINT(msg.lParam);
		//CWnd* pWndSource = CWnd::FromHandle(dd.hwndSource);
		//CWnd* pWndTarget = CWnd::FromHandle(dd.hwndTarget);
		//pWndSource->ClientToScreen(&pt);
		//pWndTarget->ScreenToClient(&pt);
		//dd.pt = pt;
		//m_pMainWnd->SendMessage(WM_DD_DRAGDROP, pWndTarget->GetDlgCtrlID(), (LPARAM)(void*)&dd);
	} else {
		SendMessage(m_pMainWnd, WM_DD_DRAGABORT, GetDlgCtrlID(dd.hwndSource), 0);
		//m_pMainWnd->SendMessage(WM_DD_DRAGABORT, 0, 0);
	}
	delete m_info.data;
	m_info.data=NULL;
	SetState(NONE);
	return TRUE;
}

//////////////////
// Change state for finite-state-machine.
//
void CDragDropMgr::SetState(UINT iState)
{
	//TRACE(_T("CDragDropMgr::SetState %d\n"),iState);
	if (iState!=m_iState) {
		if (iState==CAPTURED) {
			::SetCapture(m_hwndTracking);	 // capture mouse input

		} else if (iState==DRAGGING) {
			m_hCursorSave = GetCursor();	 // save current cursor
		
		} else if (iState==NONE) {
			::ReleaseCapture();				 // release capture and..
			SetCursor(m_hCursorSave);		 // ..restore cursor
			if (m_pDragImage) {
				ImageList_EndDrag();	 // end drawing and..
				//m_pDragImage->EndDrag();	 // end drawing and..
				//delete m_pDragImage;			 // ..destroy..
				m_pDragImage=NULL;			 // ..image list
			}
			m_hwndTracking = NULL;
		}
		m_iState = iState;
	}
}

//////////////////
// Create the drag image: create an image list and call virtual draw function
// to draw the data into the image list. Will then use this during dragging.
//
HIMAGELIST CDragDropData::CreateDragImage(HWND pWnd, RECT& rc)
//CImageList* CDragDropData::CreateDragImage(CWnd* pWnd, CRect& rc)
{
	const COLORREF BGCOLOR = GetSysColor(COLOR_3DLIGHT);

	// create memory dc compatible w/source window
	HDC dcWin = GetWindowDC(pWnd);
	HDC dcMem;
	dcMem = CreateCompatibleDC(dcWin);
	
	//CWindowDC dcWin(pWnd);
	//CDC dcMem;
	//dcMem.CreateCompatibleDC(&dcWin);

	// use same font as source window
	HFONT pFont = (HFONT) SendMessage( pWnd, WM_GETFONT, 0, 0 );
	HFONT pOldFont = (HFONT) SelectObject(dcMem,pFont);
	//CFont* pFont = pWnd->GetFont();
	//CFont* pOldFont = dcMem.SelectObject(pFont);

	// get size of drag image
	SIZE sz = OnGetDragSize(dcMem); // call virtual fn to get size
	rc.top = 0; rc.left = 0; rc.bottom = sz.cy; rc.right = sz.cx;
	//CSize sz = OnGetDragSize(dcMem); // call virtual fn to get size
	//rc = CRect(CPoint(0,0), sz);

	// create image list: create bitmap and draw into it
	m_bitmap = CreateCompatibleBitmap(dcWin, sz.cx, sz.cy);
	HBITMAP pOldBitmap = (HBITMAP) SelectObject(dcMem, m_bitmap);
	HBRUSH brush = CreateSolidBrush(GetSysColor(RGB(255, 255 ,255))); //COLOR_HIGHLIGHT));
	FillRect(dcMem,&rc,brush);
	SetBkMode(dcMem,TRANSPARENT);
	SetTextColor(dcMem,GetSysColor(RGB(0, 0 ,0))); //COLOR_WINDOWTEXT));
	OnDrawData(dcMem, rc); // call virtual fn to draw
	SelectObject(dcMem, pOldFont);
	SelectObject(dcMem, pOldBitmap);

	// create image list and add bitmap to it
	HIMAGELIST pil = ImageList_Create(sz.cx, sz.cy, ILC_COLOR24|ILC_MASK, 1, 0);
	int image_idx = ImageList_Add( pil, m_bitmap, NULL);
	//assert(image_idx >= 0);

	/*
	m_bitmap.CreateCompatibleBitmap(&dcWin, sz.cx, sz.cy);
	CBitmap* pOldBitmap = dcMem.SelectObject(&m_bitmap);
	CBrush brush;
	brush.CreateSolidBrush(GetSysColor(COLOR_HIGHLIGHT));
	dcMem.FillRect(&rc,&brush);
	dcMem.SetBkMode(TRANSPARENT);
	dcMem.SetTextColor(GetSysColor(COLOR_WINDOWTEXT));
	OnDrawData(dcMem, rc); // call virtual fn to draw
	dcMem.SelectObject(pOldFont);
	dcMem.SelectObject(pOldBitmap);

	// create image list and add bitmap to it
	CImageList *pil = new CImageList();
	pil->Create(sz.cx, sz.cy, ILC_COLOR24|ILC_MASK, 0, 1);
	pil->Add(&m_bitmap, BGCOLOR);
	*/

	return pil;
}

//////////////////
// Get draw size for text: use DrawText with DT_CALCRECT.
// this function also draws the text into the 
//
SIZE CDragDropText::OnGetDragSize(HDC & dc)
//CSize CDragDropText::OnGetDragSize(CDC& dc)
{
	RECT rc;
	rc.top = 0; rc.right = 0; rc.bottom = 0; rc.right = 0;
	//CRect rc(0,0,0,0);
	DrawText(dc, m_text, lstrlen(m_text)+1, &rc, DT_CALCRECT);
	//dc.DrawText(m_text, &rc, DT_CALCRECT);
	if (rc.right>MAXWIDTH)
		rc.right = MAXWIDTH;
	SIZE size;
	size.cx = rc.right-rc.left;
	size.cy = rc.bottom - rc.top;

	return size;
	//return rc.Size();
}

//////////////////
// Call MFC/Windows to draw text.
//
void CDragDropText::OnDrawData(HDC& dc, RECT& rc)
//void CDragDropText::OnDrawData(CDC& dc, CRect& rc)
{
	DrawText(dc, m_text, lstrlenW(m_text), &rc, DT_LEFT|DT_END_ELLIPSIS);
	//dc.DrawText(m_text, &rc, DT_LEFT|DT_END_ELLIPSIS);
}
