// DragDrop.h

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  Based on MSDN Magazine, October 2004 drag and drop code written by Paul DiLascia: Create Client Windows, Drag and Drop Between Listboxes http://msdn.microsoft.com/en-us/magazine/cc163915.aspx
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


#pragma once

#include <hash_map>
#pragma warning(disable: 4996)

#include <Commctrl.h>
#include <Windowsx.h>


// typedefs for window map: uses STL hash_map
using namespace std;
using namespace stdext;

typedef hash_map<HWND,UINT> HWNDMAP;
typedef pair<HWND,UINT> HWNDMAPENTRY;

//////////////////
// Abstract drag-drop data knows how to draw itself.
//
class CDragDropData {
protected:
	HBITMAP			m_bitmap;				 // bitmap used for drawing
	//CBitmap			m_bitmap;				 // bitmap used for drawing
public:
	CDragDropData() { }
	~CDragDropData() { }

	HIMAGELIST CreateDragImage(HWND hWnd, RECT& rc);
	//virtual CImageList* CreateDragImage(CWnd* pWnd, CRect& rc);

	// derived classes must implement these:
	virtual SIZE OnGetDragSize(HDC & dc) = 0;
	virtual void  OnDrawData(HDC & dc, RECT & rc) = 0;
	//virtual CSize OnGetDragSize(CDC& dc) = 0;
	//virtual void  OnDrawData(CDC& dc, CRect& rc) = 0;
	virtual void* OnGetData()= 0;
};

//////////////////
// Concrete class for drag-drop text data.
//
class CDragDropText : public CDragDropData {
protected:
	enum { MAXWIDTH=MAX_PATH+1 };
	LPWSTR m_text;
	//CString m_text;

public:
	
	CDragDropText(LPCTSTR text) {
		m_text = new WCHAR[MAXWIDTH];
		StringCchCopy(m_text,MAXWIDTH,text);
	}

	~CDragDropText() { delete m_text; }

	SIZE OnGetDragSize(HDC & dc);
	void  OnDrawData(HDC& dc, RECT& rc);
	//virtual CSize OnGetDragSize(CDC& dc);
	//virtual void  OnDrawData(CDC& dc, CRect& rc);
	void* OnGetData() { return (void*)(LPCTSTR) m_text; }
};

//////////////////
// registered message sent by drag-drop manager
//
//extern const UINT WM_DD_DRAGENTER; // start dragging
//extern const UINT WM_DD_DRAGOVER;  // dragging
//extern const UINT WM_DD_DRAGDROP;  // drop
//extern const UINT WM_DD_DRAGABORT; // abort dragging

#define WM_DD_DRAGENTER (WM_USER + 0x0001)
#define WM_DD_DRAGDROP (WM_USER + 0x0002)
#define WM_DD_DRAGABORT (WM_USER + 0x0003)
#define WM_DD_DRAGOVER (WM_USER + 0x0004)

// flags used for window type in window map
const UINT DDW_SOURCE = 0x01; // window is drag-drop source
const UINT DDW_TARGET = 0x02;	// window is drag-dtop target

// Used to create drag-drop window map. Map is an array of these structs,
// each entry specifies a child window ID and whether the window is a source,
// target, or both.
struct DRAGDROPWND {
	UINT id;					// window ID
	UINT type;				// DDW_ flags above
};

//////////////////
// Drag-drop structure passed as LPARAM in WM_DD_ messages.
//
struct DRAGDROPINFO {
	HWND hwndSource;		// source window
	HWND hwndTarget;		// target window
	CDragDropData* data;	// data to drag/drop
	POINT pt;				// current point (cursor) in client coords
								// of whatever window is identified by WPARAM
};

//////////////////
// Inter-app drag-drop manager. To use this, instantiate one instance in your
// main window class and call Install from your OnCreate or OnInitDialog
// method. You must also override your main window's PreTranslateMessage to
// call CDragDropMgr::PreTranslateMessage.
//
class CDragDropMgr {
protected:
	enum { NONE=0, CAPTURED, DRAGGING }; // internal states

	// static stuff 
	HWND				m_pMainWnd;				 // main window
	//CWnd*				m_pMainWnd;				 // main window
	HWNDMAP			m_mapHwnd;				 // map of source/target windows
	HCURSOR			m_hCursorDrop;			 // ok-to-drop cursor
	HCURSOR			m_hCursorNo;			 // no-drop cursor

	// dyanmic stuff used during dragging
	DRAGDROPINFO	m_info;					 // data during drag/drop
	UINT				m_iState;				 // current state: CAPTURED/DRAGGING
	HWND				m_hwndTracking;		 // window w/mouse capture
	POINT			m_ptOrg;					 // original point start of drag
	HIMAGELIST		m_pDragImage;			 // imagelist for dragging
	//CPoint			m_ptOrg;					 // original point start of drag
	//CImageList*		m_pDragImage;			 // imagelist for dragging
	HCURSOR			m_hCursorSave;			 // save cursor

	// mouse input handlers
	BOOL OnLButtonDown(const MSG& msg);
	int OnMouseMove(const MSG& msg);
	BOOL OnLButtonUp(const MSG& msg);

	// internal helper functions
	void SetState(UINT iState);
	BOOL IsCaptured() { return m_iState>=CAPTURED; }
	BOOL IsDragging() { return m_iState>=DRAGGING; }
	BOOL IsSourceWnd(HWND hwnd) {
		return GetWindowType(hwnd) & DDW_SOURCE ? TRUE : FALSE;
	}
	BOOL IsTargetWnd(HWND hwnd) {
		return GetWindowType(hwnd) & DDW_TARGET ? TRUE : FALSE;
	}
	UINT GetWindowType(HWND hwnd);

	POINT GetPoint(LPARAM lp);

public:
	BOOL m_bDrag;
	CDragDropMgr();
	virtual ~CDragDropMgr();

	// Call this to initialize. 2nd arg is array of DRAGDROPWND's, one for
	// each source/target child window.
	//
	BOOL Install(HWND pMainWnd, DRAGDROPWND* pWnds);

	// You must call this from your main window's PreTranslateMessage.
	BOOL PreTranslateMessage(MSG* pMsg);

	// Call this if you want non-standard cursors.
	void SetCursors(HCURSOR hCursorDrop, HCURSOR hCursorNo)
	{
		m_hCursorDrop = hCursorDrop;
		m_hCursorNo = hCursorNo;
	}

	// Call these to add/remove source/target windows dynamically.
	void AddWindow(HWND hwnd, int type);
	void RemoveWindow(HWND hwnd);
};
