package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modkernel32            = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess        = modkernel32.NewProc("OpenProcess")
	procWriteProcessMemory = modkernel32.NewProc("WriteProcessMemory")
	virtualAllocEx         = modkernel32.NewProc("VirtualAllocEx")

	ErrSuccess = "The operation completed successfully."
	NULL       = uintptr(0)
)

type DWORD uint32
type LPVOID uintptr
type HANDLE uintptr
type SIZE_T int

func VirtualAllocEx(hProcess HANDLE, lpAddress uintptr,
	dwSize int, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	r1, _, lastErr := virtualAllocEx.Call(uintptr(hProcess),
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if r1 == uintptr(0) {
		return r1, lastErr
	}
	return r1, nil
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (handle HANDLE, err error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}

	ret, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId))
	if err != nil && err.Error() == "The operation completed successfully." {
		err = nil
	}
	handle = HANDLE(ret)
	return
}

//Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
func WriteProcessMemory(hProcess HANDLE, lpBaseAddress uintptr,
	data []byte, size uint) (err error) {
	var numBytesRead uintptr

	fmt.Printf("WriteProcessMemory %v %0#x %0#x\n",
		hProcess, lpBaseAddress, uintptr(unsafe.Pointer(&data[0])))

	_, _, err = procWriteProcessMemory.Call(uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if err.Error() != ErrSuccess {
		return
	}
	err = nil
	return
}
