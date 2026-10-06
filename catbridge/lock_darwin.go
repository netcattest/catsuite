package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func acquireHostLock(directory string) (func(), error) {
	if e := os.MkdirAll(directory, 0700); e != nil {
		return nil, e
	}
	file, e := os.OpenFile(filepath.Join(directory, "server.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, errors.New("E_HOST_BUSY")
	}
	return func() { syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }, nil
}
