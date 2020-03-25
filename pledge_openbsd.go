package main

import "golang.org/x/sys/unix"

func PledgePromises(promises string) error {
	return unix.PledgePromises(promises)
}

func Unveil(path string, flags string) error {
	return unix.Unveil(path, flags)
}

func UnveilBlock() error {
	return unix.UnveilBlock()
}