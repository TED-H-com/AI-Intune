package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func openErrorUploadFile(path string) (*os.File, error) {
	return os.Open(path)
}

func errorFileIdentity(f *os.File, _ os.FileInfo) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d:%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}
