package main

import (
	"fmt"
	"runtime"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// TODO(toru): When I try to apply umount to ActNotify, I encounter the following error.
	// panic: numerical argument out of domain
	// var syscalls = []string{"mount", "umount", "umount2", "bind", "chown"}
	var syscalls = []string{"mount", "umount2", "bind", "chown"}
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		panic(err)
	}
	err = filter.SetNoNewPrivsBit(false)
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

	err = filter.Load()
	// TODO(toru): When I checked usign strace, I didn't have enough permissions for seccomp syscall, but it's unclear why.
	// panic: operation canceled
	//
	// if err != nil {
	// 	panic(err)
	// }

	fd, err := filter.GetNotifFd()
	if err != nil {
		panic(err)
	}

	fmt.Println("scmpFd: %w", fd)

	fmt.Println("Finish")
}
