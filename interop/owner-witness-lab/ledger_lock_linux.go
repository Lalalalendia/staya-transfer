//go:build linux

package ownerwitness

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func lockLedger(f *os.File) (func(), error) {
	for attempt := 0; attempt < 200; attempt++ {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, errors.New("Linux owner ledger lock timed out")
}
