//go:build !windows

package main

func setupPlatformLogging(daemon, console bool) error { return nil }
