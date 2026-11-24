#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")

#define MAX_THREADS 64
#define SCAN_WATCH_MS 100
#define LOG_MAX_CHARS (1024 * 1024)
#define CLIENT_W 400
#define CLIENT_H 430

#define ID_HOST_EDIT 101
#define ID_START_EDIT 102
#define ID_END_EDIT 103
#define ID_SCAN_BTN 104
#define ID_LOG_EDIT 105
#define ID_BANNER_CHECK 106
#define ID_STOP_BTN 107
#define ID_TIMEOUT_EDIT 108

#define IDT_SCANWATCH 300

#define WM_APP_SCAN_DONE (WM_APP + 1)
#define WM_APP_LOG (WM_APP + 2)
#define WM_APP_PROGRESS (WM_APP + 3)

typedef struct {
    char text[1024];
} LogMsg;

typedef struct ScanState {
    char host[256];
    struct in_addr target_addr;
    int start_port;
    int end_port;
    int timeout_ms;
    int grab_banner;
    int num_threads;
    int created_threads;
    LONG total_ports;
    volatile LONG cancel;
    volatile LONG next_port_idx;
    volatile LONG ports_done;
    volatile LONG open_count;
    volatile LONG closed_count;
    volatile LONG filtered_count;
    volatile LONG resolve_done;
    volatile LONG phase;
    volatile LONG refs;
    HANDLE h_event;
    volatile HANDLE h_cancel;
    HANDLE workers[MAX_THREADS];
} ScanState;

enum {
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_FAILED
};

enum {
    SCAN_PHASE_IDLE,
    SCAN_PHASE_RESOLVING,
    SCAN_PHASE_SCANNING
};

static HWND g_hHost, g_hStart, g_hEnd, g_hLog;
static HWND g_hScanBtn, g_hStopBtn, g_hBannerCheck, g_hTimeout;
static HWND g_hProgress;
static HWND g_hWnd;

static volatile LONG g_is_scanning = 0;
static HANDLE g_scan_thread = NULL;
static ScanState* g_active_scan = NULL;
static volatile LONG g_live_scanner_threads = 0;

static LONG read_atomic(volatile LONG* v) {
    return InterlockedCompareExchange(v, 0, 0);
}

static HANDLE read_handle(volatile HANDLE* ph) {
    return (HANDLE)InterlockedCompareExchangePointer((PVOID volatile*)ph, NULL, NULL);
}

static void state_release(ScanState* st) {
    if (InterlockedDecrement(&st->refs) == 0)
        free(st);
}

static void post_log(const char* fmt, ...) {
    LogMsg* msg = (LogMsg*)malloc(sizeof(LogMsg));
    if (!msg) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg->text, sizeof(msg->text), fmt, args);
    va_end(args);
    if (!PostMessageA(g_hWnd, WM_APP_LOG, 0, (LPARAM)msg))
        free(msg);
}

static void post_progress(LONG done, LONG total) {
    PostMessageA(g_hWnd, WM_APP_PROGRESS, (WPARAM)done, (LPARAM)total);
}

static void post_scan_done(void) {
    PostMessageA(g_hWnd, WM_APP_SCAN_DONE, 0, 0);
}

static int get_edit_int(HWND hEdit, int* out) {
    char buf[32] = {0};

    if (GetWindowTextLengthA(hEdit) >= (int)sizeof(buf)) return 0;
    if (GetWindowTextA(hEdit, buf, (int)sizeof(buf)) <= 0) return 0;
    if (buf[0] != '+' && buf[0] != '-' && (buf[0] < '0' || buf[0] > '9'))
        return 0;

    errno = 0;
    char* end = NULL;
    long val = strtol(buf, &end, 10);
    if (end == buf || *end != '\0' || errno == ERANGE) return 0;
    if (val < INT_MIN || val > INT_MAX) return 0;

    *out = (int)val;
    return 1;
}

static int get_edit_str(HWND hEdit, char* buf, int buflen) {
    int len = GetWindowTextLengthA(hEdit);
    if (len <= 0 || len >= buflen) return 0;
    GetWindowTextA(hEdit, buf, buflen);
    buf[buflen - 1] = '\0';
    return 1;
}

static void append_log(const char* text) {
    int len = GetWindowTextLengthA(g_hLog);
    if (len > LOG_MAX_CHARS) {
        SendMessageA(g_hLog, EM_SETSEL, 0, (LPARAM)(len / 2));
        SendMessageA(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)"");
        len = GetWindowTextLengthA(g_hLog);
    }
    SendMessageA(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageA(g_hLog, EM_SCROLLCARET, 0, 0);
}

static POINT window_size(int client_w, int client_h) {
    RECT rc = {0, 0, client_w, client_h};
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
    POINT pt = {rc.right - rc.left, rc.bottom - rc.top};
    return pt;
}

static int try_connect(struct in_addr addr, int port, int timeout_ms, SOCKET* out) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 2;

    u_long mode = 1;
    if (ioctlsocket(s, FIONBIO, &mode) != 0) {
        closesocket(s);
        return 2;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)port);
    sa.sin_addr = addr;

    int rc = connect(s, (struct sockaddr*)&sa, sizeof(sa));
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            closesocket(s);
            return (err == WSAECONNREFUSED) ? 0 : 2;
        }

        fd_set wfds, efds;
        FD_ZERO(&wfds); FD_SET(s, &wfds);
        FD_ZERO(&efds); FD_SET(s, &efds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select(0, NULL, &wfds, &efds, &tv);
        if (sel <= 0) {
            closesocket(s);
            return 2;
        }

        if (FD_ISSET(s, &efds)) {
            int so_err = 0, len = (int)sizeof(so_err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &len) != 0) {
                closesocket(s);
                return 2;
            }
            closesocket(s);
            return (so_err == WSAECONNREFUSED) ? 0 : 2;
        }

        if (FD_ISSET(s, &wfds)) {
            int so_err = 0, len = (int)sizeof(so_err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &len) != 0) {
                closesocket(s);
                return 2;
            }
            if (so_err == 0) {
                mode = 0;
                if (ioctlsocket(s, FIONBIO, &mode) != 0) {
                    closesocket(s);
                    return 2;
                }
                *out = s;
                return 1;
            }
            closesocket(s);
            return (so_err == WSAECONNREFUSED) ? 0 : 2;
        }
        closesocket(s);
        return 2;
    }

    mode = 0;
    if (ioctlsocket(s, FIONBIO, &mode) != 0) {
        closesocket(s);
        return 2;
    }
    *out = s;
    return 1;
}

static int grab_banner(SOCKET s, char* buf, int buflen) {
    ULONGLONG t0 = GetTickCount64();
    int total = 0;
    while (total < buflen - 1) {
        if (GetTickCount64() - t0 > 800) break;
        fd_set rfds;
        FD_ZERO(&rfds); FD_SET(s, &rfds);
        struct timeval tv = {0, 100000};
        int sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel <= 0) {
            if (sel == 0) continue;
            break;
        }
        int n = recv(s, buf + total, buflen - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        if (memchr(buf, '\n', total) || memchr(buf, '\r', total))
            break;
    }
    buf[total] = '\0';
    for (int i = 0; i < total; ++i)
        if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] == 0x7f)
            buf[i] = ' ';
    return total;
}

static unsigned WINAPI worker_thread(LPVOID param) {
    ScanState* st = (ScanState*)param;

    for (;;) {
        if (read_atomic(&st->cancel)) break;

        LONG idx = InterlockedIncrement(&st->next_port_idx) - 1;
        if (idx >= st->total_ports) break;

        int port = st->start_port + (int)idx;
        SOCKET sock = INVALID_SOCKET;
        int stat = try_connect(st->target_addr, port, st->timeout_ms, &sock);
        InterlockedIncrement(&st->ports_done);

        if (stat == 1) {
            InterlockedIncrement(&st->open_count);
            char banner[512] = {0};
            if (st->grab_banner) grab_banner(sock, banner, sizeof(banner));
            if (banner[0] != '\0')
                post_log("Open %d\t%s\r\n", port, banner);
            else
                post_log("Open %d\r\n", port);
            closesocket(sock);
        } else if (stat == 0) {
            InterlockedIncrement(&st->closed_count);
        } else {
            InterlockedIncrement(&st->filtered_count);
        }

        LONG done = read_atomic(&st->ports_done);
        if (done % 50 == 0 || done == st->total_ports)
            post_progress(done, st->total_ports);
    }

    state_release(st);
    InterlockedDecrement(&g_live_scanner_threads);
    return 0;
}

static BOOL wait_and_close_workers(ScanState* st) {
    BOOL all_synced = TRUE;
    for (int i = 0; i < st->created_threads; ++i) {
        DWORD wr = WaitForSingleObject(st->workers[i], INFINITE);
        if (wr != WAIT_OBJECT_0) {
            post_log("Error Waiting for worker thread %d of %d failed (wait result %lu).\r\n",
                     i + 1, st->created_threads, (unsigned long)wr);
            all_synced = FALSE;
            InterlockedExchange(&st->cancel, 1);
            wr = WaitForSingleObject(st->workers[i], (DWORD)st->timeout_ms + 5000);
            if (wr != WAIT_OBJECT_0) {
                post_log("Error Worker thread %d of %d could not be synchronized; "
                         "its handle and context stay alive with it until it exits.\r\n",
                         i + 1, st->created_threads);
                continue;
            }
            post_log("WARN Worker thread %d of %d synchronized on retry.\r\n",
                     i + 1, st->created_threads);
        }
        CloseHandle(st->workers[i]);
        st->workers[i] = NULL;
    }
    return all_synced;
}

static int valid_host(const char* host) {
    for (const char* p = host; *p; ++p)
        if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
            return 0;
    return 1;
}

static unsigned WINAPI scan_thread(LPVOID param) {
    ScanState* st = (ScanState*)param;
    int status = SCAN_STATUS_FAILED;

    InterlockedExchange(&st->phase, SCAN_PHASE_RESOLVING);
    post_log("Resolving %s...\r\n", st->host);

    wchar_t wname[256];
    int wn = MultiByteToWideChar(CP_UTF8, 0, st->host, -1, wname, (int)ARRAYSIZE(wname));
    if (wn <= 0) {
        post_log("Error Cannot convert hostname '%s' (error %lu).\r\n",
                 st->host, (unsigned long)GetLastError());
        InterlockedExchange(&st->resolve_done, 1);
        goto finish;
    }

    ADDRINFOEXW hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    PADDRINFOEXW ares = NULL;
    HANDLE hCancelOut = NULL;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = st->h_event;

    int rc = GetAddrInfoExW(wname, NULL, NS_ALL, NULL, &hints, &ares,
                            NULL, &ov, NULL, &hCancelOut);
    if (hCancelOut)
        InterlockedExchangePointer((PVOID volatile*)&st->h_cancel, (PVOID)hCancelOut);

    if (rc == WSA_IO_PENDING) {
        DWORD wr = WaitForSingleObject(st->h_event, INFINITE);
        if (wr != WAIT_OBJECT_0) {
            if (hCancelOut) GetAddrInfoExCancel(hCancelOut);
            post_log("Error Waiting for DNS lookup completion failed (wait result %lu).\r\n",
                     (unsigned long)wr);
            goto finish;
        }
        InterlockedExchange(&st->resolve_done, 1);
    } else if (rc != NO_ERROR) {
        post_log("Error Cannot resolve %s (GetAddrInfoEx error %d).\r\n", st->host, rc);
        InterlockedExchange(&st->resolve_done, 1);
        goto finish;
    }
    if (rc == NO_ERROR)
        InterlockedExchange(&st->resolve_done, 1);

    if (ares == NULL) {
        if (read_atomic(&st->cancel)) {
            post_log("Scan cancelled during DNS resolution.\r\n");
            status = SCAN_STATUS_CANCELLED;
        } else {
            post_log("Error Cannot resolve %s (lookup failed or was cancelled).\r\n",
                     st->host);
        }
        goto finish;
    }

    if (read_atomic(&st->cancel)) {
        FreeAddrInfoExW(ares);
        post_log("Scan cancelled during DNS resolution.\r\n");
        status = SCAN_STATUS_CANCELLED;
        goto finish;
    }

    if (ares->ai_family != AF_INET || ares->ai_addr == NULL ||
        ares->ai_addrlen < sizeof(struct sockaddr_in)) {
        post_log("Error Resolver returned an unexpected address format for %s.\r\n",
                 st->host);
        FreeAddrInfoExW(ares);
        goto finish;
    }

    st->target_addr = ((struct sockaddr_in*)ares->ai_addr)->sin_addr;
    FreeAddrInfoExW(ares);

    char ipbuf[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &st->target_addr, ipbuf, sizeof(ipbuf)) == NULL)
        post_log("Target: %s address could not be converted to text\r\n", st->host);
    else
        post_log("Target: %s (%s)\r\n", st->host, ipbuf);

    st->total_ports = (LONG)st->end_port - (LONG)st->start_port + 1;
    InterlockedExchange(&st->next_port_idx, 0);
    InterlockedExchange(&st->ports_done, 0);
    InterlockedExchange(&st->open_count, 0);
    InterlockedExchange(&st->closed_count, 0);
    InterlockedExchange(&st->filtered_count, 0);
    memset(st->workers, 0, sizeof(st->workers));
    st->created_threads = 0;

    InterlockedExchange(&st->phase, SCAN_PHASE_SCANNING);

    int created = 0;
    for (int i = 0; i < st->num_threads; ++i) {
        InterlockedIncrement(&g_live_scanner_threads);
        InterlockedIncrement(&st->refs);
        uintptr_t th = _beginthreadex(NULL, 0, worker_thread, st, 0, NULL);
        if (th != 0) {
            st->workers[created++] = (HANDLE)th;
        } else {
            InterlockedDecrement(&g_live_scanner_threads);
            InterlockedDecrement(&st->refs);
        }
    }
    st->created_threads = created;

    if (created == 0) {
        post_log("Error Failed to create worker threads. Scan aborted.\r\n");
        goto finish;
    }
    if (created < st->num_threads)
        post_log("WARN Only %d of %d requested worker threads could be created.\r\n",
                 created, st->num_threads);

    post_log("Scanning ports %d-%d with %d worker threads, timeout %d ms...\r\n",
             st->start_port, st->end_port, created, st->timeout_ms);

    BOOL all_synced = wait_and_close_workers(st);
    if (all_synced)
        status = read_atomic(&st->cancel) ? SCAN_STATUS_CANCELLED : SCAN_STATUS_COMPLETED;
    else
        status = SCAN_STATUS_FAILED;

    LONG done = read_atomic(&st->ports_done);
    LONG open = read_atomic(&st->open_count);
    LONG closed = read_atomic(&st->closed_count);
    LONG filtered = read_atomic(&st->filtered_count);

    if (status == SCAN_STATUS_COMPLETED) {
        post_log("\r\nScan complete: %ld open, %ld closed, %ld filtered "
                 "%ld of %ld ports\r\n",
                 open, closed, filtered, done, st->total_ports, created);
    } else if (status == SCAN_STATUS_CANCELLED) {
        post_log("\r\nScan cancelled after %ld of %ld ports: "
                 "%ld open, %ld closed, %ld filtered.\r\n",
                 done, st->total_ports, open, closed, filtered);
    } else {
        post_log("\r\nError Scan FAILED: worker threads could not be synchronized. "
                 "Partial counts: %ld open, %ld closed, %ld filtered.\r\n",
                 open, closed, filtered);
    }

finish:
    InterlockedExchange(&st->phase, SCAN_PHASE_IDLE);
    post_progress(read_atomic(&st->ports_done), st->total_ports);
    post_scan_done();
    state_release(st);
    InterlockedDecrement(&g_live_scanner_threads);
    return 0;
}

static void set_inputs_enabled(BOOL on) {
    EnableWindow(g_hScanBtn, on);
    EnableWindow(g_hStopBtn, !on);
    EnableWindow(g_hHost, on);
    EnableWindow(g_hStart, on);
    EnableWindow(g_hEnd, on);
    EnableWindow(g_hTimeout, on);
    EnableWindow(g_hBannerCheck, on);
}

static void finalize_scan(void) {
    if (InterlockedCompareExchange(&g_is_scanning, 0, 1) != 1) return;

    ScanState* st = g_active_scan;
    if (g_scan_thread) {
        DWORD wr = WaitForSingleObject(g_scan_thread, INFINITE);
        if (wr == WAIT_OBJECT_0) {
            CloseHandle(g_scan_thread);
        } else {
            post_log("Error Waiting for the scan thread failed (wait result %lu); "
                     "handle left open.\r\n", (unsigned long)wr);
        }
        g_scan_thread = NULL;
    }

    KillTimer(g_hWnd, IDT_SCANWATCH);

    if (st) {
        if (st->h_event) {
            if (read_atomic(&st->resolve_done)) {
                CloseHandle(st->h_event);
            } else {
                DWORD wr = WaitForSingleObject(st->h_event, 5000);
                if (wr == WAIT_OBJECT_0)
                    CloseHandle(st->h_event);
                else
                    post_log("WARN DNS completion was never delivered; the event "
                             "handle is left to the OS at process exit.\r\n");
            }
            st->h_event = NULL;
        }
        HANDLE hc = read_handle(&st->h_cancel);
        if (hc) CloseHandle(hc);
        state_release(st);
    }
    g_active_scan = NULL;

    set_inputs_enabled(TRUE);
}

static void start_scan(void) {
    if (InterlockedCompareExchange(&g_is_scanning, 1, 0) != 0) return;

    int start_port, end_port, timeout_ms;
    char host[256];

    if (!get_edit_str(g_hHost, host, sizeof(host))) {
        if (GetWindowTextLengthA(g_hHost) == 0)
            post_log("Error Host cannot be empty.\r\n");
        else
            post_log("Error Host is too long (maximum 255 characters).\r\n");
        InterlockedExchange(&g_is_scanning, 0);
        return;
    }

    if (!valid_host(host)) {
        post_log("Error Host contains invalid characters.\r\n");
        InterlockedExchange(&g_is_scanning, 0);
        return;
    }

    if (!get_edit_int(g_hStart, &start_port) || start_port < 1 || start_port > 65535) {
        post_log("Error Invalid start port.\r\n");
        InterlockedExchange(&g_is_scanning, 0);
        return;
    }

    if (!get_edit_int(g_hEnd, &end_port) || end_port < 1 || end_port > 65535 ||
        end_port < start_port) {
        post_log("Error Invalid end port.\r\n");
        InterlockedExchange(&g_is_scanning, 0);
        return;
    }

    if (!get_edit_int(g_hTimeout, &timeout_ms) || timeout_ms < 50 || timeout_ms > 10000) {
        post_log("Error Invalid timeout (50-10000 ms).\r\n");
        InterlockedExchange(&g_is_scanning, 0);
        return;
    }

    ScanState* st = (ScanState*)calloc(1, sizeof(ScanState));
    if (!st) {
        post_log("Error Out of memory.\r\n");
        InterlockedExchange(&g_is_scanning, 0);
        return;
    }

    strncpy(st->host, host, sizeof(st->host) - 1);
    st->host[sizeof(st->host) - 1] = '\0';
    st->start_port = start_port;
    st->end_port = end_port;
    st->timeout_ms = timeout_ms;
    st->grab_banner = (SendMessageA(g_hBannerCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    st->num_threads = MAX_THREADS;

    int total = st->end_port - st->start_port + 1;
    if (total < st->num_threads) st->num_threads = total;

    st->refs = 1;

    st->h_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!st->h_event) {
        post_log("Error Cannot create the DNS completion event.\r\n");
        state_release(st);
        InterlockedExchange(&g_is_scanning, 0);
        return;
    }

    if (!SetTimer(g_hWnd, IDT_SCANWATCH, SCAN_WATCH_MS, NULL))
        post_log("WARN Watchdog timer could not be created; completion relies "
                 "on the notification message.\r\n");

    g_active_scan = st;

    SendMessageA(g_hLog, WM_SETTEXT, 0, (LPARAM)"");
    if (g_hProgress) SendMessageA(g_hProgress, PBM_SETPOS, 0, 0);

    set_inputs_enabled(FALSE);

    InterlockedIncrement(&g_live_scanner_threads);
    InterlockedIncrement(&st->refs);
    uintptr_t th = _beginthreadex(NULL, 0, scan_thread, st, 0, NULL);
    if (th == 0) {
        post_log("Error Failed to create scan thread.\r\n");
        InterlockedDecrement(&g_live_scanner_threads);
        InterlockedDecrement(&st->refs);
        KillTimer(g_hWnd, IDT_SCANWATCH);
        CloseHandle(st->h_event);
        state_release(st);
        g_active_scan = NULL;
        InterlockedExchange(&g_is_scanning, 0);
        set_inputs_enabled(TRUE);
        return;
    }
    g_scan_thread = (HANDLE)th;
}

static void stop_scan(void) {
    ScanState* st = g_active_scan;
    if (!st) return;

    if (InterlockedExchange(&st->cancel, 1) == 0) {
        if (read_atomic(&st->phase) == SCAN_PHASE_RESOLVING) {
            HANDLE hc = read_handle(&st->h_cancel);
            if (hc) GetAddrInfoExCancel(hc);
            post_log("Stop requested during DNS resolution; cancelling the lookup.\r\n");
        }
    }
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hWnd = hWnd;
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        HWND hHostLabel = CreateWindowA("STATIC", "Host/IP:", WS_CHILD | WS_VISIBLE,
                                        12, 16, 60, 20, hWnd, NULL, NULL, NULL);
        g_hHost = CreateWindowA("EDIT", "127.0.0.1",
                                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP,
                                72, 12, 206, 24, hWnd, (HMENU)(INT_PTR)ID_HOST_EDIT, NULL, NULL);

        HWND hStartLabel = CreateWindowA("STATIC", "Start Port:", WS_CHILD | WS_VISIBLE,
                                         12, 50, 60, 20, hWnd, NULL, NULL, NULL);
        g_hStart = CreateWindowA("EDIT", "1",
                                 WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER | WS_TABSTOP,
                                 72, 46, 58, 24, hWnd, (HMENU)(INT_PTR)ID_START_EDIT, NULL, NULL);

        HWND hEndLabel = CreateWindowA("STATIC", "End Port:", WS_CHILD | WS_VISIBLE,
                                       136, 50, 60, 20, hWnd, NULL, NULL, NULL);
        g_hEnd = CreateWindowA("EDIT", "1024",
                               WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER | WS_TABSTOP,
                               196, 46, 58, 24, hWnd, (HMENU)(INT_PTR)ID_END_EDIT, NULL, NULL);

        HWND hTimeoutLabel = CreateWindowA("STATIC", "Timeout (ms):", WS_CHILD | WS_VISIBLE,
                                           258, 50, 74, 20, hWnd, NULL, NULL, NULL);
        g_hTimeout = CreateWindowA("EDIT", "250",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER | WS_TABSTOP,
                                   334, 46, 54, 24, hWnd, (HMENU)(INT_PTR)ID_TIMEOUT_EDIT, NULL, NULL);

        g_hBannerCheck = CreateWindowA("BUTTON", "Grab Info By > z01309z",
                                       WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP,
                                       15, 87, 130, 20, hWnd,
                                       (HMENU)(INT_PTR)ID_BANNER_CHECK, NULL, NULL);

        g_hScanBtn = CreateWindowA("BUTTON", "START SCAN",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
                                   290, 12, 98, 26, hWnd,
                                   (HMENU)(INT_PTR)ID_SCAN_BTN, NULL, NULL);
        g_hStopBtn = CreateWindowA("BUTTON", "STOP",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED | WS_TABSTOP,
                                   290, 80, 98, 26, hWnd,
                                   (HMENU)(INT_PTR)ID_STOP_BTN, NULL, NULL);

        g_hProgress = CreateWindowExA(0, PROGRESS_CLASS, NULL, WS_CHILD | WS_VISIBLE,
                                      12, 116, 376, 16, hWnd, NULL, NULL, NULL);

        g_hLog = CreateWindowA("EDIT", "",
                               WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL |
                               ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                               12, 142, 376, 276, hWnd,
                               (HMENU)(INT_PTR)ID_LOG_EDIT, NULL, NULL);

        SendMessageA(g_hHost, EM_SETLIMITTEXT, 255, 0);
        SendMessageA(g_hStart, EM_SETLIMITTEXT, 6, 0);
        SendMessageA(g_hEnd, EM_SETLIMITTEXT, 6, 0);
        SendMessageA(g_hTimeout, EM_SETLIMITTEXT, 5, 0);
        SendMessageA(g_hLog, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);

        HWND hFontTargets[] = { hHostLabel, hStartLabel, hEndLabel, hTimeoutLabel,
                                g_hHost, g_hStart, g_hEnd, g_hTimeout,
                                g_hBannerCheck, g_hScanBtn, g_hStopBtn, g_hLog };
        for (int i = 0; i < (int)ARRAYSIZE(hFontTargets); ++i)
            SendMessageA(hFontTargets[i], WM_SETFONT, (WPARAM)hFont, TRUE);
        if (g_hProgress) SendMessageA(g_hProgress, WM_SETFONT, (WPARAM)hFont, TRUE);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_SCAN_BTN)
            start_scan();
        else if (LOWORD(wParam) == ID_STOP_BTN)
            stop_scan();
        break;
    case WM_TIMER:
        if (wParam == IDT_SCANWATCH && g_is_scanning && g_scan_thread &&
            WaitForSingleObject(g_scan_thread, 0) == WAIT_OBJECT_0)
            finalize_scan();
        break;
    case WM_APP_LOG: {
        LogMsg* lm = (LogMsg*)lParam;
        if (lm) {
            append_log(lm->text);
            free(lm);
        }
        break;
    }
    case WM_APP_PROGRESS: {
        LONG done = (LONG)wParam;
        LONG total = (LONG)lParam;
        if (g_hProgress && total > 0)
            SendMessageA(g_hProgress, PBM_SETPOS, (WPARAM)((done * 100) / total), 0);
        break;
    }
    case WM_APP_SCAN_DONE:
        finalize_scan();
        break;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize = window_size(CLIENT_W, CLIENT_H);
        break;
    }
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            break;
        if (g_hLog && g_hProgress) {
            MoveWindow(g_hProgress, 12, 116, LOWORD(lParam) - 24, 16, TRUE);
            MoveWindow(g_hLog, 12, 142, LOWORD(lParam) - 24, HIWORD(lParam) - 154, TRUE);
        }
        break;
    case WM_DESTROY: {
        ScanState* st = g_active_scan;
        if (st) {
            InterlockedExchange(&st->cancel, 1);
            if (read_atomic(&st->phase) == SCAN_PHASE_RESOLVING) {
                HANDLE hc = read_handle(&st->h_cancel);
                if (hc) GetAddrInfoExCancel(hc);
            }
        }
        finalize_scan();
        MSG pending;
        while (PeekMessageA(&pending, g_hWnd, WM_APP_LOG, WM_APP_LOG, PM_REMOVE)) {
            LogMsg* lm = (LogMsg*)pending.lParam;
            free(lm);
        }
        PostQuitMessage(0);
        break;
    }
    default:
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxA(NULL, "WSAStartup failed.", "Error", MB_ICONERROR);
        return 1;
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS };
    if (!InitCommonControlsEx(&icc))
        MessageBoxA(NULL, "Common controls could not be initialized; the progress "
                          "bar may be unavailable.", "Warning", MB_ICONWARNING);

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "PortScannerGUI";

    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class.", "Error", MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    POINT sz = window_size(CLIENT_W, CLIENT_H);
    HWND hWnd = CreateWindowA("PortScannerGUI", "Port Scanner", WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, sz.x, sz.y,
                              NULL, NULL, hInstance, NULL);
    if (!hWnd) {
        MessageBoxA(NULL, "Failed to create window.", "Error", MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    BOOL ret;
    while ((ret = GetMessageA(&msg, NULL, 0, 0)) > 0) {
        if (IsDialogMessageA(hWnd, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    if (read_atomic(&g_live_scanner_threads) == 0)
        WSACleanup();
    return (ret == -1) ? 1 : (int)msg.wParam;
}
