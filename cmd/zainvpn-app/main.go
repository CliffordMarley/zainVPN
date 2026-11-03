//go:build windows

// Command zainvpn-app is the zainVPN desktop window. It shows the local UI that
// the zainVPN service serves on 127.0.0.1:7779 in a WebView2 window. Closing
// the window doesn't stop the VPN; the service keeps running.
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const (
	title  = "zainVPN"
	uiURL  = "http://127.0.0.1:7779/"
	iconID = 1 // RT_GROUP_ICON #1 in rsrc_windows_amd64.syso
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	findWindow       = user32.NewProc("FindWindowW")
	showWindow       = user32.NewProc("ShowWindow")
	setForeground    = user32.NewProc("SetForegroundWindow")
	messageBox       = user32.NewProc("MessageBoxW")
	shell32          = windows.NewLazySystemDLL("shell32.dll")
	shellExecute     = shell32.NewProc("ShellExecuteW")
	client           = &http.Client{Timeout: 1500 * time.Millisecond}
	errServiceFailed = "zainVPN still isn't responding. Try again, or reinstall zainVPN."
)

func main() {
	name, _ := windows.UTF16PtrFromString(`Local\zainVPN-App`)
	if _, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		focusExisting()
		return
	}

	data := filepath.Join(os.Getenv("LOCALAPPDATA"), "zainVPN", "WebView2")
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  data,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: title, Width: 1040, Height: 760, IconId: iconID, Center: true,
		},
	})
	if w == nil {
		if msg("zainVPN needs the Microsoft Edge WebView2 Runtime, which isn't installed.\n\nOpen zainVPN in your web browser instead?", 0x24) == 6 { // MB_YESNO|MB_ICONQUESTION, IDYES
			open(uiURL)
		}
		return
	}
	defer w.Destroy()
	w.SetSize(720, 520, webview2.HintMin)

	// Used by the "zainVPN isn't running" page.
	w.Bind("zvRetry", func() bool {
		if serviceUp() {
			w.Dispatch(func() { w.Navigate(uiURL) })
			return true
		}
		return false
	})
	w.Bind("zvStart", func() string {
		exe, err := os.Executable()
		if err != nil {
			return err.Error()
		}
		// "install" recreates and starts the service from the saved settings.
		if err := runElevated(filepath.Join(filepath.Dir(exe), "zainvpn.exe"), "install"); err != nil {
			return "zainVPN couldn't be started: " + err.Error()
		}
		for range 40 {
			if serviceUp() {
				w.Dispatch(func() { w.Navigate(uiURL) })
				return ""
			}
			time.Sleep(500 * time.Millisecond)
		}
		return errServiceFailed
	})

	if serviceUp() {
		w.Navigate(uiURL)
	} else {
		w.SetHtml(notRunningPage)
	}
	w.Run()
}

func serviceUp() bool {
	resp, err := client.Get(uiURL + "api/status")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// focusExisting brings the already open zainVPN window to the front.
func focusExisting() {
	t, _ := windows.UTF16PtrFromString(title)
	hwnd, _, _ := findWindow.Call(0, uintptr(unsafe.Pointer(t)))
	if hwnd != 0 {
		showWindow.Call(hwnd, 9) // SW_RESTORE
		setForeground.Call(hwnd)
	}
}

func runElevated(exe, args string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	r, _, err := shellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, 0)
	if r <= 32 {
		if errno, ok := err.(syscall.Errno); ok && errno != 0 {
			return errno
		}
		return syscall.Errno(r)
	}
	return nil
}

func open(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	u, _ := windows.UTF16PtrFromString(url)
	shellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(u)), 0, 0, 1)
}

func msg(text string, flags uintptr) uintptr {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	r, _, _ := messageBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
	return r
}

const notRunningPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><title>zainVPN</title>
<style>
:root{--bg:#f2f3f3;--surface:#fff;--text:#000716;--text-2:#5f6b7a;--link:#0972d3;--primary:#ff9900;--primary-hover:#ec7211;--nav:#232f3e;--error:#d91515;--shadow:0 0 1px 1px rgba(0,7,22,.08),0 1px 8px 2px rgba(0,7,22,.12)}
@media (prefers-color-scheme:dark){:root{--bg:#0f1b2a;--surface:#192534;--text:#d1d5db;--text-2:#8d99a8;--link:#539fe5;--nav:#0f1b2a;--error:#ff5d64}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/20px "Amazon Ember","Helvetica Neue",Roboto,Arial,sans-serif}
header{height:48px;display:flex;align-items:center;gap:10px;padding:0 20px;background:var(--nav);color:#fff;font-weight:700;font-size:16px}
main{max-width:560px;margin:64px auto;padding:0 16px}
.c{background:var(--surface);border-radius:16px;box-shadow:var(--shadow);padding:16px 20px 20px}
h1{font-size:18px;margin:0 0 4px}p{margin:0 0 16px;color:var(--text-2)}
button{min-height:32px;padding:4px 20px;border-radius:20px;font:inherit;font-weight:700;cursor:pointer;border:2px solid var(--primary);background:var(--primary);color:#000716}
button:hover{background:var(--primary-hover);border-color:var(--primary-hover)}button:disabled{opacity:.6;cursor:default}
a{color:var(--link);font-weight:700;margin-left:16px;cursor:pointer}#err{color:var(--error);margin-top:12px}
</style></head><body>
<header><svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true"><rect width="24" height="24" rx="5" fill="#ff9900"/><path d="M7 7h10L7 17h10" fill="none" stroke="#232f3e" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>zainVPN</header>
<main><div class="c" role="alert">
<h1>zainVPN isn't running</h1>
<p>The zainVPN background service isn't responding. It normally starts with Windows; you can start it now (Windows will ask for permission).</p>
<button id="start">Start zainVPN</button><a id="retry">Try again</a>
<div id="err" aria-live="polite"></div>
</div></main>
<script>
const b = document.getElementById('start'), e = document.getElementById('err');
b.onclick = async () => { b.disabled = true; b.textContent = 'Starting…'; e.textContent = ''; const m = await zvStart(); if (m) { e.textContent = m; b.disabled = false; b.textContent = 'Start zainVPN'; } };
document.getElementById('retry').onclick = async () => { e.textContent = ''; if (!(await zvRetry())) e.textContent = 'Still not running.'; };
setInterval(() => zvRetry(), 4000);
</script></body></html>`
