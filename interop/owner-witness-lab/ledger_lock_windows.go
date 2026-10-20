//go:build windows

package ownerwitness

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	windowsLockExclusive       = 0x2
	windowsLockFailImmediately = 0x1
)

var (
	windowsKernel32     = syscall.NewLazyDLL("kernel32.dll")
	windowsLockFileEx   = windowsKernel32.NewProc("LockFileEx")
	windowsUnlockFileEx = windowsKernel32.NewProc("UnlockFileEx")
)

// Lock a byte range extending well beyond the maximum journal size: the
// entire read/append/readback must serialize across independent Windows OS
// processes. A DIFFERENT path/inode can still bypass this lock unless the
// owner installation separately controls its namespace and full ancestry.
func lockLedger(f *os.File) (func(), error) {
	ov := &syscall.Overlapped{}
	for attempt := 0; attempt < 200; attempt++ {
		ok, _, callErr := windowsLockFileEx.Call(
			uintptr(f.Fd()), windowsLockExclusive|windowsLockFailImmediately, 0,
			uintptr(0xffffffff), uintptr(0x7fffffff), uintptr(unsafe.Pointer(ov)))
		if ok != 0 {
			return func() {
				_, _, _ = windowsUnlockFileEx.Call(
					uintptr(f.Fd()), 0, uintptr(0xffffffff), uintptr(0x7fffffff), uintptr(unsafe.Pointer(ov)))
			}, nil
		}
		if callErr != syscall.Errno(33) && callErr != syscall.Errno(997) {
			return nil, callErr
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, errors.New("Windows owner ledger lock timed out")
}
