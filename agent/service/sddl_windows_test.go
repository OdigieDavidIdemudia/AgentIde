//go:build windows

package service

import (
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func daclACEInfo(t *testing.T, sddl string) (present bool, count int) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SDDL did not parse (%q): %v", sddl, err)
	}
	var dacl *windows.ACL
	var daclPresent, daclDefaulted uint32
	r1, _, e := syscall.SyscallN(
		procGetSecurityDescriptorDacl.Addr(),
		uintptr(unsafe.Pointer(sd)),
		uintptr(unsafe.Pointer(&daclPresent)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&daclDefaulted)),
	)
	if r1 == 0 {
		t.Fatalf("GetSecurityDescriptorDacl failed: %v", e)
	}
	if daclPresent == 0 || dacl == nil {
		return false, 0
	}
	return true, int(dacl.AceCount)
}

func TestHardServiceSDDLParses(t *testing.T) {
	present, count := daclACEInfo(t, hardServiceSDDL)
	if !present {
		t.Fatal("hardServiceSDDL has no DACL")
	}
	// 3 deny ACEs (SY: stop / change-config / delete) + 3 allow ACEs.
	if count != 6 {
		t.Fatalf("hardServiceSDDL: expected 6 ACEs, got %d", count)
	}
}

func TestFullServiceSDDLParses(t *testing.T) {
	present, count := daclACEInfo(t, fullServiceSDDL)
	if !present {
		t.Fatal("fullServiceSDDL has no DACL")
	}
	if count != 2 {
		t.Fatalf("fullServiceSDDL: expected 2 ACEs, got %d", count)
	}
}
