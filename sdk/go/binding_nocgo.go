// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && !cgo

package pithhash

import (
	"errors"
	"unsafe"
)

// The pure-Go fallback: without cgo there is no dynamic loader on
// unix, so every binding reports the loader error. Build with cgo
// enabled (the default) to reach the cdylib.

var errNoLoader = errors.New(
	"pithhash: CGO_ENABLED=0 build cannot load the Rust cdylib; build with cgo (or use the windows binding)",
)

// ffiSymbols resolves every exported symbol of one loaded cdylib.
func ffiSymbols(_ unsafe.Pointer, _ string) ([]unsafe.Pointer, error) {
	return nil, errNoLoader
}

// openCdylib reports the missing dynamic-loader capability.
func openCdylib(string) (unsafe.Pointer, error) {
	return nil, errNoLoader
}

// resolve reports the missing dynamic-loader capability.
func resolve(_ string, _ int) (unsafe.Pointer, error) {
	return nil, errNoLoader
}

// ffiDetect reports the missing dynamic-loader capability.
func ffiDetect(_ string, _ *byte, _ int, _, _, _ *uint32) (int32, error) {
	return 0, errNoLoader
}

// ffiStream reports the missing dynamic-loader capability.
func ffiStream(_, _ string, _ *byte, _ int, _ **byte, _ *uint64) (int32, error) {
	return 0, errNoLoader
}

// ffiMatch reports the missing dynamic-loader capability.
func ffiMatch(_ string, _ *byte, _ int, _ *byte, _ int, _ *uint32, _ *uint64, _ uint64, _ *uint32) (int32, error) {
	return 0, errNoLoader
}

// ffiContentHash reports the missing dynamic-loader capability.
func ffiContentHash(_ string, _ *byte, _ int, _ *byte, _ uint64, _ *uint64) (int32, error) {
	return 0, errNoLoader
}

// ffiFree reports the missing dynamic-loader capability.
func ffiFree(_ string, _ *byte, _ uint64) {}
