package main

import (
	"fmt"
	"runtime"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func main() {
	runtime.LockOSThread()
	var syscalls = []string{"mount"}
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		panic(err)
	}
	err = filter.SetTsync(false)
	if err != nil {
		panic(err)
	}
	for _, syscall := range syscalls {
		fmt.Printf("ActNotify: %s\n", syscall)
		syscallID, err := libseccomp.GetSyscallFromName(syscall)
		if err != nil {
			panic(err)
		}
		err = filter.AddRuleExact(syscallID, libseccomp.ActNotify)
		if err != nil {
			panic(err)
		}
	}
	filter.Load()
	fmt.Println("Finish")
}
