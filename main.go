package main

import (
	"fmt"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func main() {
	var syscalls = []string{"mount"}
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
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
