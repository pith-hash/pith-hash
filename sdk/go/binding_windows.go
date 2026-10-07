// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build windows

package pithhash

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procLoadLibraryW   = kernel32.NewProc("LoadLibraryW")
	procGetProcAddress = kernel32.NewProc("GetProcAddress")
	procFreeLibrary    = kernel32.NewProc("FreeLibrary")
)

// ffiSymbols resolves every exported symbol of one loaded cdylib.
func ffiSymbols(handle uintptr, libPath string) ([]uintptr, error) {
	syms := make([]uintptr, len(cdylibSymbols))
	for i, name := range cdylibSymbols {
		ptr, _, err := procGetProcAddress.Call(handle, uintptr(unsafe.Pointer(syscall.StringBytePtr(name))))
		if ptr == 0 {
			return nil, fmt.Errorf("pithhash: symbol %s missing from %s: %v", name, libPath, err)
		}
		syms[i] = ptr
	}
	return syms, nil
}

// openCdylib LoadLibraryWs libPath with error text surfaced verbatim.
func openCdylib(libPath string) (uintptr, error) {
	pathPtr, err := syscall.UTF16PtrFromString(libPath)
	if err != nil {
		return 0, fmt.Errorf("pithhash: bad library path %q: %w", libPath, err)
	}
	handle, _, callErr := procLoadLibraryW.Call(uintptr(unsafe.Pointer(pathPtr)))
	if handle == 0 {
		return 0, fmt.Errorf("pithhash: LoadLibrary(%s): %v", libPath, callErr)
	}
	return handle, nil
}

// The resolved symbol table is cached for the process lifetime: the
// loader handle is intentionally never released, because FreeLibrary
// would unmap the cdylib and leave resolved pointers dangling.
var (
	symbolsOnce sync.Once
	symbols     []uintptr
	symbolsErr  error
)

// resolve opens the cdylib once, resolves the symbols and returns the
// requested one (index into cdylibSymbols).
func resolve(libPath string, index int) (uintptr, error) {
	symbolsOnce.Do(func() {
		handle, err := openCdylib(libPath)
		if err != nil {
			symbolsErr = err
			return
		}
		symbols, symbolsErr = ffiSymbols(handle, libPath)
	})
	if symbolsErr != nil {
		return 0, symbolsErr
	}
	return symbols[index], nil
}

// ffiDetect loads the cdylib and calls pith_hash_detect.
func ffiDetect(libPath string, data *byte, n int, format, modality, pending *uint32) (int32, error) {
	fn, err := resolve(libPath, 0)
	if err != nil {
		return 0, err
	}
	r1, _, _ := syscall.SyscallN(fn,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(format)),
		uintptr(unsafe.Pointer(modality)),
		uintptr(unsafe.Pointer(pending)),
	)
	return int32(r1), nil
}

// ffiStream calls the named stream op (pith_hash_signature or
// pith_hash_describe) and hands back the cdylib-owned buffer.
func ffiStream(libPath, op string, data *byte, n int, out **byte, outLen *uint64) (int32, error) {
	index := -1
	for i, name := range cdylibSymbols {
		if name == op {
			index = i
		}
	}
	if index < 0 {
		return 0, fmt.Errorf("pithhash: unknown stream op %s", op)
	}
	fn, err := resolve(libPath, index)
	if err != nil {
		return 0, err
	}
	r1, _, _ := syscall.SyscallN(fn,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(out)),
		uintptr(unsafe.Pointer(outLen)),
	)
	return int32(r1), nil
}

// ffiMatch loads the cdylib and calls pith_hash_match.
func ffiMatch(libPath string, a *byte, aLen int, b *byte, bLen int, tag *uint32, slots *uint64, cap uint64, matched *uint32) (int32, error) {
	fn, err := resolve(libPath, 3)
	if err != nil {
		return 0, err
	}
	r1, _, _ := syscall.SyscallN(fn,
		uintptr(unsafe.Pointer(a)),
		uintptr(aLen),
		uintptr(unsafe.Pointer(b)),
		uintptr(bLen),
		uintptr(unsafe.Pointer(tag)),
		uintptr(unsafe.Pointer(slots)),
		uintptr(cap),
		uintptr(unsafe.Pointer(matched)),
	)
	return int32(r1), nil
}

// ffiContentHash loads the cdylib and calls pith_hash_content_hash.
func ffiContentHash(libPath string, data *byte, n int, out *byte, capacity uint64, outLen *uint64) (int32, error) {
	fn, err := resolve(libPath, 4)
	if err != nil {
		return 0, err
	}
	r1, _, _ := syscall.SyscallN(fn,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(out)),
		uintptr(capacity),
		uintptr(unsafe.Pointer(outLen)),
	)
	return int32(r1), nil
}

// ffiFree releases a buffer handed out by ffiStream. Null is accepted
// (the cdylib ignores it), matching the C contract.
func ffiFree(libPath string, ptr *byte, n uint64) {
	fn, err := resolve(libPath, 5)
	if err != nil {
		return // the library vanished mid-flight; nothing to free
	}
	syscall.SyscallN(fn, uintptr(unsafe.Pointer(ptr)), uintptr(n))
}
