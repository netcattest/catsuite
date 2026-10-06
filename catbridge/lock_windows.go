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
	path, e := syscall.UTF16PtrFromString(filepath.Join(directory, "server.lock"))
	if e != nil {
		return nil, e
	}
	handle, e := syscall.CreateFile(path, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, errors.New("E_HOST_BUSY")
	}
	return func() { syscall.CloseHandle(handle) }, nil
}
