package utils

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import "unsafe"

func myByteCopy(dst []byte, src []byte) {
	cpylen := len(src)
	if len(dst) < len(src) {
		cpylen = len(dst)
	} else {
		cpylen = len(src)
	}
	C.memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), C.size_t(cpylen))
}

func myStringCopy(dst []string, src []string) {
	cpylen := len(src)
	if len(dst) < len(src) {
		cpylen = len(dst)
	} else {
		cpylen = len(src)
	}
	C.memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), C.size_t(cpylen))
}
