//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Microsoft/hcsshim/osversion"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	cimimport "github.com/Microsoft/hcsshim/pkg/ociwclayer/cim"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

type ParentLayers []*cimfs.BlockCIM

var (
	checkWindowsVersionOnce sync.Once
	windowsVersionError     error
)

// checkWindowsVersion verifies that we're running on Windows Server 2025 (build 26100)
// with UBR (Update Build Revision) >= 32800.
// CIM file generation on older versions will not produce deterministic hashes.
// Returns an error if the version requirement is not met, unless debug mode is enabled.
func checkWindowsVersion() error {
	checkWindowsVersionOnce.Do(func() {
		ver := windows.RtlGetVersion()
		if ver == nil {
			windowsVersionError = fmt.Errorf("failed to get Windows version information")
			return
		}

		build := ver.BuildNumber
		requiredBuild := uint32(26100)
		requiredUBR := uint32(32800)

		// Windows Server 2025 is build 26100
		// Deterministic CIM file generation requires build == 26100 with UBR >= 32800
		if build != requiredBuild {
			if debugSkipVersionCheck {
				log.WithFields(log.Fields{
					"current_build":  build,
					"required_build": requiredBuild,
					"debug_mode":     true,
				}).Warn("DEBUG MODE: Not running on WS2025 build 26100. Hashes may not be deterministic. This is for development/testing only.")
				windowsVersionError = nil
			} else {
				windowsVersionError = fmt.Errorf(
					"Windows Server 2025 (build %d) is required for deterministic Windows container hashes. "+
						"Current build: %d. Windows platform processing cannot continue on this version.",
					requiredBuild, build,
				)
				log.WithFields(log.Fields{
					"current_build":  build,
					"required_build": requiredBuild,
				}).Error("Incorrect Windows build for deterministic CIM generation")
			}
			return
		}

		ubr, err := osversion.BuildRevision()
		if err != nil {
			if debugSkipVersionCheck {
				log.WithField("error", err).Warn("DEBUG MODE: Failed to read UBR from registry. Continuing anyway.")
				windowsVersionError = nil
			} else {
				windowsVersionError = fmt.Errorf("failed to read Update Build Revision (UBR) from registry: %w", err)
			}
			return
		}

		if ubr < requiredUBR {
			if debugSkipVersionCheck {
				log.WithFields(log.Fields{
					"current_ubr":  ubr,
					"required_ubr": requiredUBR,
					"debug_mode":   true,
				}).Warn("DEBUG MODE: UBR is below minimum required. Hashes may not be deterministic. This is for development/testing only.")
				windowsVersionError = nil
			} else {
				windowsVersionError = fmt.Errorf(
					"Windows Server 2025 build %d with UBR >= %d is required for deterministic Windows container hashes. "+
						"Current UBR: %d. Please install the latest Windows updates.",
					requiredBuild, requiredUBR, ubr,
				)
				log.WithFields(log.Fields{
					"current_build": build,
					"current_ubr":   ubr,
					"required_ubr":  requiredUBR,
				}).Error("Insufficient UBR for deterministic CIM generation")
			}
			return
		}

		log.WithFields(log.Fields{
			"build": build,
			"ubr":   ubr,
		}).Debug("Windows version check passed")
	})
	return windowsVersionError
}

// orderedParentsForMerge returns the parent layers in immediate-parent-first order
// (the reverse of confcom's base-first accumulation).
//
// hcsshim's processNonBaseLayer merges each layer's registry delta against
// parentLayerPaths[0] (see internal/wclayer/cim/process.go), and
// MergeBlockCIMLayersWithOpts expects source CIMs in topmost-first order (base at
// the last index). The cplat runtime (blockcim snapshotter) supplies parents in
// containerd parent-chain order, i.e. immediate-parent-first, so [0] is the
// previous layer's already-merged hive, producing a cumulative/chained registry
// merge. confcom accumulates parents base-first, which would merge every delta
// against the original base hive (a flat merge) and diverge from the runtime at
// the third layer onward. Reversing to immediate-parent-first makes confcom's
// per-layer and merged block-CIM hashes match the runtime exactly.
func orderedParentsForMerge(parentLayers ParentLayers) ParentLayers {
	reversed := make(ParentLayers, len(parentLayers))
	for i, pl := range parentLayers {
		reversed[len(parentLayers)-1-i] = pl
	}
	return reversed
}

func tarToCim(tarReader io.Reader, parentLayers ParentLayers, out string, layerName string) (string, ParentLayers, error) {
	log.Trace("tarToCim called")

	// Check Windows version for deterministic hash support
	if err := checkWindowsVersion(); err != nil {
		return "", parentLayers, err
	}

	// If no out path is given, use a temp directory
	var err error
	if out == "" {
		out, err = os.MkdirTemp("", "cim")
		if err != nil {
			return "", parentLayers, fmt.Errorf("failed to create temp directory: %w", err)
		}
	}

	if layerName == "" {
		layerName = filepath.Base(out)
	}
	layerName = sanitizeCimLayerName(layerName)
	blockFileName := fmt.Sprintf("%s.bcim", layerName)
	// The CIM name is part of the dm-verity-hashed content. The cplat runtime
	// blockcim snapshotter names every layer CIM "layer.cim"; match it so the
	// per-layer roothash equals the runtime's integrity_checksum.
	cimName := "layer.cim"
	blockPath := filepath.Join(out, blockFileName)

	blockCIM := &cimfs.BlockCIM{
		Type:      cimfs.BlockCIMTypeSingleFile,
		BlockPath: blockPath,
		CimName:   cimName,
	}

	importOpts := []cimimport.BlockCIMLayerImportOpt{
		cimimport.WithParentLayers(orderedParentsForMerge(parentLayers)),
		cimimport.WithVHDFooter(),
		cimimport.WithLayerIntegrity(),
	}

	log.Tracef("before cimimport.ImportBlockCIMLayerWithOpts for layer %s cim name %s", layerName, cimName)
	size, importErr := cimimport.ImportBlockCIMLayerWithOpts(context.Background(), tarReader, blockCIM, importOpts...)
	log.Tracef("after cimimport.ImportBlockCIMLayerWithOpts for layer %s, size %d", layerName, size)
	if importErr != nil {
		return "", parentLayers, fmt.Errorf("layer (%s): %w", layerName, importErr)
	}

	digest, err := cimimport.GetIntegrityChecksum(context.Background(), blockPath, "")
	if err != nil {
		return "", parentLayers, fmt.Errorf("failed to read integrity_checksum for layer %s: %w", layerName, err)
	}

	parentLayers = append(parentLayers, blockCIM)

	return strings.TrimSpace(string(digest)), parentLayers, nil
}

func generateMergedCim(parentLayers ParentLayers, out string, mergedName string) (string, error) {
	log.Trace("generateMergedCim called")

	// Check Windows version for deterministic hash support
	if err := checkWindowsVersion(); err != nil {
		return "", err
	}

	if mergedName == "" {
		mergedName = "merged"
	}
	mergedName = sanitizeCimLayerName(mergedName)
	blockFileName := fmt.Sprintf("%s.bcim", mergedName)
	cimName := fmt.Sprintf("%s.cim", mergedName)
	blockPath := filepath.Join(out, blockFileName)

	mergedBlockCIM := &cimfs.BlockCIM{
		Type:      cimfs.BlockCIMTypeSingleFile,
		BlockPath: blockPath,
		CimName:   cimName,
	}

	importOpts := []cimimport.BlockCIMLayerImportOpt{
		cimimport.WithParentLayers(parentLayers),
		cimimport.WithVHDFooter(),
		cimimport.WithLayerIntegrity(),
	}

	log.Tracef("before cimimport.MergeBlockCIMLayersWithOpts for merged layer %s", mergedName)
	// MergeBlockCIMLayersWithOpts (like the cplat snapshotter's prepareMergedCIM)
	// expects source CIMs in topmost-first order (base at the last index); confcom
	// accumulates parentLayers base-first, so reverse to match the runtime's merged
	// CIM bytes and hash.
	importErr := cimimport.MergeBlockCIMLayersWithOpts(context.Background(), orderedParentsForMerge(parentLayers), mergedBlockCIM, importOpts...)
	log.Tracef("after cimimport.MergeBlockCIMLayersWithOpts for merged layer %s", mergedName)

	if importErr != nil {
		return "", fmt.Errorf("merged layer (%s): %w", mergedName, importErr)
	}

	digest, err := cimimport.GetIntegrityChecksum(context.Background(), blockPath, "")
	if err != nil {
		return "", fmt.Errorf("failed to read integrity_checksum for merged layer %s: %w", mergedName, err)
	}

	return strings.TrimSpace(string(digest)), nil
}

func sanitizeCimLayerName(name string) string {
	log.Trace("sanitizeCimLayerName called")

	name = filepath.Base(name)
	if idx := strings.LastIndex(name, ":"); idx != -1 {
		name = name[idx+1:]
	}
	replacer := strings.NewReplacer(
		":", "_",
		"<", "_",
		">", "_",
		"\"", "_",
		"/", "_",
		"\\", "_",
		"|", "_",
		"?", "_",
		"*", "_",
	)
	name = replacer.Replace(name)
	if name == "" {
		return "layer"
	}
	return name
}
