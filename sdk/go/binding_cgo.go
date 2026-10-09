// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && cgo

package pithhash

/*
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*pith_detect_fn)(const uint8_t *, size_t, uint32_t *, uint32_t *, uint32_t *);
typedef int32_t (*pith_stream_fn)(const uint8_t *, size_t, uint8_t **, size_t *);
typedef int32_t (*pith_match_fn)(const uint8_t *, size_t, const uint8_t *, size_t,
                                 uint32_t *, uint64_t *, size_t, uint32_t *);
typedef int32_t (*pith_hash_fn)(const uint8_t *, size_t, uint8_t *, size_t, size_t *);
typedef void (*pith_free_fn)(uint8_t *, size_t);

static int32_t pith_call_detect(void *fn, const uint8_t *data, size_t len,
                                uint32_t *format, uint32_t *modality, uint32_t *pending) {
    return ((pith_detect_fn)fn)(data, len, format, modality, pending);
}

static int32_t pith_call_stream(void *fn, const uint8_t *data, size_t len,
                                uint8_t **out, size_t *out_len) {
    return ((pith_stream_fn)fn)(data, len, out, out_len);
}

static int32_t pith_call_match(void *fn, const uint8_t *a, size_t a_len,
                               const uint8_t *b, size_t b_len, uint32_t *tag,
                               uint64_t *slots, size_t cap, uint32_t *matched) {
    return ((pith_match_fn)fn)(a, a_len, b, b_len, tag, slots, cap, matched);
}

static int32_t pith_call_hash(void *fn, const uint8_t *data, size_t len,
                              uint8_t *out, size_t cap, size_t *out_len) {
    return ((pith_hash_fn)fn)(data, len, out, cap, out_len);
}

static void pith_call_free(void *fn, uint8_t *ptr, size_t len) {
    ((pith_free_fn)fn)(ptr, len);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// ffiSymbols resolves every exported symbol of one open cdylib handle.
func ffiSymbols(handle unsafe.Pointer, libPath string) ([]unsafe.Pointer, error) {
	syms := make([]unsafe.Pointer, len(cdylibSymbols))
	for i, name := range cdylibSymbols {
		cName := C.CString(name)
		sym := C.dlsym(handle, cName)
		C.free(unsafe.Pointer(cName))
		if sym == nil {
			return nil, fmt.Errorf("pithhash: symbol %s missing from %s", name, libPath)
		}
		syms[i] = sym
	}
	return syms, nil
}

// openCdylib dlopens libPath with error text surfaced verbatim.
func openCdylib(libPath string) (unsafe.Pointer, error) {
	cPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cPath))
	handle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		msg := "unknown dlopen failure"
		if e := C.dlerror(); e != nil {
			msg = C.GoString(e)
		}
		return nil, fmt.Errorf("pithhash: dlopen(%s): %s", libPath, msg)
	}
	return handle, nil
}

// The resolved symbol table is cached for the process lifetime: the
// loader handle is intentionally never released, because FreeLibrary
// would unmap the cdylib and leave resolved pointers dangling.
var (
	symbolsOnce sync.Once
	symbols     []unsafe.Pointer
	symbolsErr  error
)

// resolve opens the cdylib once, resolves the symbols and returns the
// requested one (index into cdylibSymbols).
func resolve(libPath string, index int) (unsafe.Pointer, error) {
	symbolsOnce.Do(func() {
		handle, err := openCdylib(libPath)
		if err != nil {
			symbolsErr = err
			return
		}
		symbols, symbolsErr = ffiSymbols(handle, libPath)
	})
	if symbolsErr != nil {
		return nil, symbolsErr
	}
	return symbols[index], nil
}

// ffiDetect loads the cdylib and calls pith_hash_detect.
func ffiDetect(libPath string, data *byte, n int, format, modality, pending *uint32) (int32, error) {
	fn, err := resolve(libPath, 0)
	if err != nil {
		return 0, err
	}
	rc := C.pith_call_detect(fn, (*C.uint8_t)(unsafe.Pointer(data)), C.size_t(n),
		(*C.uint32_t)(unsafe.Pointer(format)), (*C.uint32_t)(unsafe.Pointer(modality)),
		(*C.uint32_t)(unsafe.Pointer(pending)))
	return int32(rc), nil
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
		return 0, errors.New("pithhash: unknown stream op " + op)
	}
	fn, err := resolve(libPath, index)
	if err != nil {
		return 0, err
	}
	var cOut *C.uint8_t
	var cLen C.size_t
	rc := C.pith_call_stream(fn, (*C.uint8_t)(unsafe.Pointer(data)), C.size_t(n), &cOut, &cLen)
	*out = (*byte)(unsafe.Pointer(cOut))
	*outLen = uint64(cLen)
	return int32(rc), nil
}

// ffiMatch loads the cdylib and calls pith_hash_match.
func ffiMatch(libPath string, a *byte, aLen int, b *byte, bLen int, tag *uint32, slots *uint64, cap uint64, matched *uint32) (int32, error) {
	fn, err := resolve(libPath, 3)
	if err != nil {
		return 0, err
	}
	rc := C.pith_call_match(fn,
		(*C.uint8_t)(unsafe.Pointer(a)), C.size_t(aLen),
		(*C.uint8_t)(unsafe.Pointer(b)), C.size_t(bLen),
		(*C.uint32_t)(unsafe.Pointer(tag)), (*C.uint64_t)(unsafe.Pointer(slots)),
		C.size_t(cap), (*C.uint32_t)(unsafe.Pointer(matched)))
	return int32(rc), nil
}

// ffiContentHash loads the cdylib and calls pith_hash_content_hash.
func ffiContentHash(libPath string, data *byte, n int, out *byte, capacity uint64, outLen *uint64) (int32, error) {
	fn, err := resolve(libPath, 4)
	if err != nil {
		return 0, err
	}
	rc := C.pith_call_hash(fn, (*C.uint8_t)(unsafe.Pointer(data)), C.size_t(n),
		(*C.uint8_t)(unsafe.Pointer(out)), C.size_t(capacity), (*C.size_t)(unsafe.Pointer(outLen)))
	return int32(rc), nil
}

// ffiFree releases a buffer handed out by ffiStream. Null is accepted
// (the cdylib ignores it), matching the C contract.
func ffiFree(libPath string, ptr *byte, n uint64) {
	fn, err := resolve(libPath, 5)
	if err != nil {
		return // the library vanished mid-flight; nothing to free
	}
	C.pith_call_free(fn, (*C.uint8_t)(unsafe.Pointer(ptr)), C.size_t(n))
}
