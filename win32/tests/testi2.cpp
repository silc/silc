// testi2.cpp : Defines the entry point for the application.
//

#define FD_SETSIZE 5000
#include "stdafx.h"
#include "resource.h"
#include <winsock2.h>
#include <mswsock.h>
extern "C"
{
#define FD_SETSIZE 5000
#include "silcincludes.h"
#include "clientlibincludes.h"
}

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];								// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];								// The title bar text

// Foward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

void silc_op_say(SilcClient client, SilcClientConnection conn, 
                 SilcClientMessageType type, char *msg, ...)
{
	va_list vp;
	char message[2048];

	memset(message, 0, sizeof(message));
	strncat(message, "\n***  ", 5);

	va_start(vp, msg);
	vsprintf(message + 5, msg, vp);
	va_end(vp);

	MessageBox( NULL, (char *)message, "say", MB_OK | MB_ICONINFORMATION );
}

void silc_notify(SilcClient client, SilcClientConnection conn, 
		 SilcNotifyType type, ...)
{

}

void silc_connect(SilcClient client, SilcClientConnection conn, int success)
{

}

int silc_auth_meth(SilcClient client, SilcClientConnection conn,
			 char *hostname, SilcUInt16 port,
			 SilcProtocolAuthMeth *auth_meth,
			 unsigned char **auth_data,
			 SilcUInt32 *auth_data_len)
{
    *auth_meth = SILC_AUTH_NONE;
	return TRUE;
}
void silc_verify_public_key(SilcClient client, SilcClientConnection conn,
			    SilcSocketType conn_type, unsigned char *pk, 
			    SilcUInt32 pk_len, SilcSKEPKType pk_type,
			    SilcVerifyPublicKey completion, void *context)
{
  completion(TRUE, context);
}

void silc_command_reply(SilcClient client, SilcClientConnection conn,
			SilcCommandPayload cmd_payload, int success,
			SilcCommand command, SilcCommandStatus status, ...)
{

}

/* SILC client operations */
SilcClientOperations ops = {
  silc_op_say,
	NULL,
	NULL,
	silc_notify,
	NULL,
	silc_command_reply,
	silc_connect,
	NULL,
	silc_auth_meth,
	silc_verify_public_key,
};

SILC_TASK_CALLBACK(connect_client)
{
  SilcClient client = (SilcClient)context;
	silc_client_connect_to_server(client, 1334, "leevi.kuo.fi.ssh.com", NULL);
}

void silc_log(char *message)
{
}

void silc_debugl(char *file, char *function, 
								int line, char *message)
{
	char m[5000];
	memcpy(m, message, strlen(message));
	m[strlen(message)] = '\n';
	m[strlen(message) + 1] = 0;
	OutputDebugString(m);
}

void silc_hexdumpl(char *file, char *function, 
							   int line, unsigned char *data_in,
							   SilcUInt32 data_len, char *message)
{
  int i, k;
  int off, pos, count;
  unsigned char *data = (unsigned char *)data_in;
	char m[10000], *cp;
	int len = data_len;
	
//	memset(m, 0, sizeof(m));

	cp = m;
  snprintf(cp, 10000, "%s:%d: %s\n", function, line, message);
	cp += strlen(cp);

  k = 0;
  off = len % 16;
  pos = 0;
  count = 16;
  while (1) {

    if (off) {
      if ((len - pos) < 16 && (len - pos <= len - off))
				count = off;
    } else {
      if (pos == len)
				count = 0;
    }
    if (off == len)
      count = len;

    if (count) {
      snprintf(cp, sizeof(m), "%08X  ", k++ * 16);
			cp += strlen(cp);
		}

    for (i = 0; i < count; i++) {
      snprintf(cp, sizeof(m), "%02X ", data[pos + i]);
			cp += strlen(cp);
      
      if ((i + 1) % 4 == 0) {
				snprintf(cp, sizeof(m), " ");
				cp += strlen(cp);
			}
		}

    if (count && count < 16) {
      int j;
      
      for (j = 0; j < 16 - count; j++) {
				snprintf(cp, sizeof(m), "   ");
				cp += strlen(cp);
		
				if ((j + count + 1) % 4 == 0) {
					snprintf(cp, sizeof(m), " ");
					cp += strlen(cp);
				}
			}
    }
	  
    for (i = 0; i < count; i++) {
      char ch;
      
      if (data[pos] < 32 || data[pos] >= 127)
				ch = '.';
      else
				ch = data[pos];

      snprintf(cp, sizeof(m), "%c", ch);
 			cp += strlen(cp);
      pos++;
    }

    if (count) {
      snprintf(cp, sizeof(m), "\n");
 			cp += strlen(cp);
		}

    if (count < 16)
      break;
  }
	
	OutputDebugString(m);
	MessageBox( NULL, (char *)m, "hexdump", MB_OK | MB_ICONINFORMATION );
}

static int 
silc_create_key_pair(char *pkcs_name, int bits, char *path,
                            char *identifier, 
                            SilcPublicKey *ret_pub_key,
                            SilcPrivateKey *ret_prv_key)
{
  SilcPKCS pkcs;
  SilcPublicKey pub_key;
  SilcPrivateKey prv_key;
  SilcRng rng;
  unsigned char *key;
  SilcUInt32 key_len;
  char pkfile[256], prvfile[256];

  if (!pkcs_name || !path)
    return FALSE;

  if (!bits)
    bits = 1024;

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_rng_global_init(rng);

  /* Generate keys */
  silc_pkcs_alloc((const unsigned char *)pkcs_name, &pkcs);
  pkcs->pkcs->init(pkcs->context, bits, rng);

  /* Save public key into file */
  key = silc_pkcs_get_public_key(pkcs, &key_len);
  pub_key = silc_pkcs_public_key_alloc(pkcs->pkcs->name, identifier,
                                       key, key_len);
  *ret_pub_key = pub_key;

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  /* Save private key into file */
  key = silc_pkcs_get_private_key(pkcs, &key_len);
  prv_key = silc_pkcs_private_key_alloc(pkcs->pkcs->name, key, key_len);
  *ret_prv_key = prv_key;

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  silc_rng_free(rng);
  silc_pkcs_free(pkcs);

  return TRUE;
}


int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;
	HANDLE h;
	HANDLE handles[100];
	SOCKET s;
	unsigned int k;
	WSAEVENT e, e2, e3;
	int ret;
	DWORD ready;
	HMODULE mod;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_TESTI2, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow)) 
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, (LPCTSTR)IDC_TESTI2);

	{
		SilcSchedule sched;	
		SilcClient client;

		silc_net_win32_init();
		client = silc_client_alloc(&ops, NULL, NULL, "SILC-1.0-0.5.1");
		client->realname = "pekka riikonen";
		client->username = "priikone";
		client->hostname = "leevi.kuo.fi.ssh.com";

		silc_cipher_register_default();
		silc_pkcs_register_default();
		silc_hash_register_default();
		silc_hmac_register_default();

		silc_debug = TRUE;
		silc_log_set_debug_callbacks(silc_debugl, silc_hexdumpl);

		silc_create_key_pair("rsa", 1024, "kk", "UN=priikone, HN=pelle.kuo.fi.ssh.com", 
												&client->public_key, &client->private_key);

		silc_client_init(client);

		silc_schedule_task_add(client->schedule, 0, connect_client, 
								client, 0, 1, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL); 

		silc_client_run(client);		
	}
	
	return msg.wParam;
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage is only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX); 

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, (LPCTSTR)IDI_TESTI2);
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= (LPCSTR)IDC_TESTI2;
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDI_SMALL);

	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HANDLE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
			LPVOID lpMsgBuf;
			FormatMessage( 
			  FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			  FORMAT_MESSAGE_FROM_SYSTEM | 
			  FORMAT_MESSAGE_IGNORE_INSERTS,
			  NULL,
			  GetLastError(),
			  0, // Default language
			  (LPTSTR) &lpMsgBuf,
			  0,
			  NULL 
			);
			// Process any inserts in lpMsgBuf.
			// ...
			// Display the string.
			MessageBox( NULL, (LPCTSTR)lpMsgBuf, "Error", MB_OK | MB_ICONINFORMATION );
			// Free the buffer.
			LocalFree( lpMsgBuf );

      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, unsigned, WORD, LONG)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;
	TCHAR szHello[MAX_LOADSTRING];
	LoadString(hInst, IDS_HELLO, szHello, MAX_LOADSTRING);

	switch (message) 
	{
		case WM_COMMAND:
			wmId    = LOWORD(wParam); 
			wmEvent = HIWORD(wParam); 
			// Parse the menu selections:
			switch (wmId)
			{
				case IDM_ABOUT:
				   DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hWnd, (DLGPROC)About);
				   break;
				case IDM_EXIT:
				   DestroyWindow(hWnd);
				   break;
				default:
				   return DefWindowProc(hWnd, message, wParam, lParam);
			}
			break;
		case WM_PAINT:
			hdc = BeginPaint(hWnd, &ps);
			// TODO: Add any drawing code here...
			RECT rt;
			GetClientRect(hWnd, &rt);
			DrawText(hdc, szHello, strlen(szHello), &rt, DT_CENTER);
			EndPaint(hWnd, &ps);
			break;
		case WM_DESTROY:
			PostQuitMessage(0);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
   }
   return 0;
}

// Mesage handler for about box.
LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_INITDIALOG:
				return TRUE;

		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) 
			{
				EndDialog(hDlg, LOWORD(wParam));
				return TRUE;
			}
			break;
	}
    return FALSE;
}
