// hive-merge exercises the Windows offline-registry (OR*) hive merge that CIM
// layer generation relies on: open a base + delta hive, ORMergeHives, then
// ORSaveHive. Running it twice on the same base + delta and comparing SHA256
// isolates whether the hive merge itself is deterministic, independent of the
// full CIM/image pipeline.
//
// The offline-registry functions live in offreg.dll; they are bound directly
// here (rather than pulling in hcsshim's internal winapi package) so the tool
// is self-contained within this module.
//
// Usage:
//
//	hive-merge.exe <base> <delta> <merged>   // merge delta into base, write merged
//	hive-merge.exe --generate-sample-input <base> <delta>   // write a small sample pair
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// orHKey is a handle to an offline registry hive (OROpenHive/ORMergeHives result).
type orHKey uintptr

const regSZ = 1 // REG_SZ

var (
	modoffreg = windows.NewLazySystemDLL("offreg.dll")

	procOROpenHive   = modoffreg.NewProc("OROpenHive")
	procORMergeHives = modoffreg.NewProc("ORMergeHives")
	procORSaveHive   = modoffreg.NewProc("ORSaveHive")
	procORCloseHive  = modoffreg.NewProc("ORCloseHive")
	procORCreateHive = modoffreg.NewProc("ORCreateHive")
	procORCreateKey  = modoffreg.NewProc("ORCreateKey")
	procORSetValue   = modoffreg.NewProc("ORSetValue")
	procORCloseKey   = modoffreg.NewProc("ORCloseKey")
)

// orOpenHive opens the hive file at hivePath and returns its handle.
func orOpenHive(hivePath string, result *orHKey) error {
	p, err := syscall.UTF16PtrFromString(hivePath)
	if err != nil {
		return err
	}
	r0, _, _ := syscall.SyscallN(procOROpenHive.Addr(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(result)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// orMergeHives merges the given hives (in order) into a new in-memory hive.
func orMergeHives(hiveHandles []orHKey, result *orHKey) error {
	var first *orHKey
	if len(hiveHandles) > 0 {
		first = &hiveHandles[0]
	}
	r0, _, _ := syscall.SyscallN(procORMergeHives.Addr(), uintptr(unsafe.Pointer(first)), uintptr(len(hiveHandles)), uintptr(unsafe.Pointer(result)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// orSaveHive writes the hive to hivePath in the format for the given OS version.
func orSaveHive(handle orHKey, hivePath string, osMajorVersion, osMinorVersion uint32) error {
	p, err := syscall.UTF16PtrFromString(hivePath)
	if err != nil {
		return err
	}
	r0, _, _ := syscall.SyscallN(procORSaveHive.Addr(), uintptr(handle), uintptr(unsafe.Pointer(p)), uintptr(osMajorVersion), uintptr(osMinorVersion))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// orCloseHive releases a hive handle.
func orCloseHive(handle orHKey) error {
	r0, _, _ := syscall.SyscallN(procORCloseHive.Addr(), uintptr(handle))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// orCreateHive creates a new, empty in-memory hive.
func orCreateHive(result *orHKey) error {
	r0, _, _ := syscall.SyscallN(procORCreateHive.Addr(), uintptr(unsafe.Pointer(result)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// orCreateKey creates (or opens) subKey under handle and returns its handle.
func orCreateKey(handle orHKey, subKey string, result *orHKey) error {
	p, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return err
	}
	var disposition uint32
	r0, _, _ := syscall.SyscallN(procORCreateKey.Addr(), uintptr(handle), uintptr(unsafe.Pointer(p)), 0, 0, 0, uintptr(unsafe.Pointer(result)), uintptr(unsafe.Pointer(&disposition)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// orSetStringValue sets a REG_SZ value on the given key.
func orSetStringValue(handle orHKey, name, value string) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	v, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	data := (*byte)(unsafe.Pointer(&v[0]))
	dataLen := uint32(len(v) * 2)
	r0, _, _ := syscall.SyscallN(procORSetValue.Addr(), uintptr(handle), uintptr(unsafe.Pointer(n)), regSZ, uintptr(unsafe.Pointer(data)), uintptr(dataLen))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

// orCloseKey releases a key handle.
func orCloseKey(handle orHKey) error {
	r0, _, _ := syscall.SyscallN(procORCloseKey.Addr(), uintptr(handle))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

func mergeHive(parentHivePath, deltaHivePath, mergedHivePath string) (err error) {
	var baseHive, deltaHive, mergedHive orHKey
	if err := orOpenHive(parentHivePath, &baseHive); err != nil {
		return fmt.Errorf("failed to open base hive %s: %w", parentHivePath, err)
	}
	defer func() {
		err2 := orCloseHive(baseHive)
		if err == nil && err2 != nil {
			err = fmt.Errorf("failed to close base hive: %w", err2)
		}
	}()
	if err := orOpenHive(deltaHivePath, &deltaHive); err != nil {
		return fmt.Errorf("failed to open delta hive %s: %w", deltaHivePath, err)
	}
	defer func() {
		err2 := orCloseHive(deltaHive)
		if err == nil && err2 != nil {
			err = fmt.Errorf("failed to close delta hive: %w", err2)
		}
	}()
	if err := orMergeHives([]orHKey{baseHive, deltaHive}, &mergedHive); err != nil {
		return fmt.Errorf("failed to merge hives: %w", err)
	}
	defer func() {
		err2 := orCloseHive(mergedHive)
		if err == nil && err2 != nil {
			err = fmt.Errorf("failed to close merged hive: %w", err2)
		}
	}()
	ver := windows.RtlGetVersion()
	// ORSaveHive fails if the target already exists; replace any prior output.
	_ = os.Remove(mergedHivePath)
	if err := orSaveHive(mergedHive, mergedHivePath, ver.MajorVersion, ver.MinorVersion); err != nil {
		return fmt.Errorf("failed to save hive: %w", err)
	}
	return
}

// writeHive builds an in-memory hive from keys (subkey -> value name -> value)
// and saves it to path.
func writeHive(path string, keys map[string]map[string]string) (err error) {
	var hive orHKey
	if err := orCreateHive(&hive); err != nil {
		return fmt.Errorf("failed to create hive: %w", err)
	}
	defer func() {
		err2 := orCloseHive(hive)
		if err == nil && err2 != nil {
			err = fmt.Errorf("failed to close hive: %w", err2)
		}
	}()
	for subKey, values := range keys {
		var key orHKey
		if err := orCreateKey(hive, subKey, &key); err != nil {
			return fmt.Errorf("failed to create key %s: %w", subKey, err)
		}
		for name, value := range values {
			if err := orSetStringValue(key, name, value); err != nil {
				_ = orCloseKey(key)
				return fmt.Errorf("failed to set value %s: %w", name, err)
			}
		}
		if err := orCloseKey(key); err != nil {
			return fmt.Errorf("failed to close key %s: %w", subKey, err)
		}
	}
	ver := windows.RtlGetVersion()
	// ORSaveHive fails if the target already exists; replace any prior output.
	_ = os.Remove(path)
	if err := orSaveHive(hive, path, ver.MajorVersion, ver.MinorVersion); err != nil {
		return fmt.Errorf("failed to save hive %s: %w", path, err)
	}
	return
}

// generateSampleInput writes a small base + delta hive pair, standing in for the
// per-layer SYSTEM_BASE/SYSTEM_DELTA files produced during CIM generation. The
// delta overlays a value and adds a key, mimicking a layer delta.
func generateSampleInput(basePath, deltaPath string) error {
	if err := writeHive(basePath, map[string]map[string]string{
		"Sample": {"DisplayName": "Sample Service", "ImagePath": "system32\\sample.sys"},
	}); err != nil {
		return err
	}
	return writeHive(deltaPath, map[string]map[string]string{
		"Sample": {"DisplayName": "Sample Service (patched)"},
		"Extra":  {"DisplayName": "Extra Service"},
	})
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  hive-merge <base> <delta> <merged>\n")
	fmt.Fprintf(os.Stderr, "  hive-merge --generate-sample-input <base> <delta>\n")
}

func main() {
	generateSample := flag.Bool("generate-sample-input", false, "write a small sample <base> <delta> hive pair instead of merging")
	flag.Usage = usage
	flag.Parse()

	if *generateSample {
		if flag.NArg() != 2 {
			usage()
			os.Exit(2)
		}
		basePath, deltaPath := flag.Arg(0), flag.Arg(1)
		if err := generateSampleInput(basePath, deltaPath); err != nil {
			fmt.Printf("failed to generate sample input: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote sample hives [%s] and [%s]\n", basePath, deltaPath)
		return
	}

	if flag.NArg() != 3 {
		usage()
		os.Exit(2)
	}
	baseHivePath, deltaHivePath, destHivePath := flag.Arg(0), flag.Arg(1), flag.Arg(2)

	fmt.Printf("Merging hive at path [%s], with hive at path [%s]...\n", baseHivePath, deltaHivePath)
	if err := mergeHive(baseHivePath, deltaHivePath, destHivePath); err != nil {
		fmt.Printf("failed to merge hives: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Merge complete. Merged hive is stored at [%s]\n", destHivePath)
}
