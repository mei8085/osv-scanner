package osvscanner

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scanner/v2/internal/imodels"
)

// packageCoordinates is the normalized OSV identity of a package: its
// ecosystem, name and version as they are queried against vulnerability
// databases. Lockfiles from different ecosystems may use the same package
// name and version, so all three fields together determine which package a
// vulnerability belongs to; comparing on name and version alone would attach
// one ecosystem's vulnerabilities to the other ecosystem's package.
type packageCoordinates struct {
	ecosystem string
	name      string
	version   string
}

// coordinatesOf returns the normalized OSV coordinates of a package. It uses
// the same normalization as the rest of the scan pipeline
// (imodels.ParsePackage, which wraps the matchers' osvutil normalization and
// additionally restores ecosystems carried in package metadata), so coordinate
// equality matches the package identity reported in the results.
func coordinatesOf(p *extractor.Package) packageCoordinates {
	np := imodels.ParsePackage(p)

	return packageCoordinates{
		ecosystem: np.Ecosystem.String(),
		name:      np.Name,
		version:   np.Version,
	}
}

// compareCoordinates compares two packages by their normalized ecosystem,
// name and version, in that order.
func compareCoordinates(a, b *extractor.Package) int {
	ca := coordinatesOf(a)
	cb := coordinatesOf(b)

	return cmp.Or(
		cmp.Compare(ca.ecosystem, cb.ecosystem),
		cmp.Compare(ca.name, cb.name),
		cmp.Compare(ca.version, cb.version),
	)
}

// InventorySort is a comparator function for Inventories, to be used in
// tests with cmp.Diff to disregard the order in which the Inventories
// are reported.
func inventorySort(a, b *extractor.Package) int {
	aLoc := a.Location.PathOrEmpty()
	bLoc := b.Location.PathOrEmpty()

	var aExtr, bExtr string
	var aPURL, bPURL string

	aPURLStruct := a.PURL()
	bPURLStruct := b.PURL()

	if aPURLStruct != nil {
		aPURL = aPURLStruct.String()
	}

	if bPURLStruct != nil {
		bPURL = bPURLStruct.String()
	}

	aSourceCode := fmt.Sprintf("%v", a.SourceCode)
	bSourceCode := fmt.Sprintf("%v", b.SourceCode)

	return cmp.Or(
		cmp.Compare(aLoc, bLoc),
		compareCoordinates(a, b),
		cmp.Compare(aSourceCode, bSourceCode),
		cmp.Compare(aExtr, bExtr),
		cmp.Compare(aPURL, bPURL),
	)
}

// mergeDuplicatePackages collapses packages that refer to the same package
// instance, i.e. packages extracted from the same lockfile location whose
// normalized OSV coordinates (ecosystem, name and version) are identical.
//
// Packages are intentionally NOT merged when their coordinates differ, even
// when they share a name, version and location: lockfiles for different
// ecosystems can use the same names for entirely different dependencies, and
// merging them would cause one ecosystem's vulnerabilities to be reported
// against the other ecosystem's package. Likewise, the same dependency found
// in separate lockfiles (different locations) is kept as a separate package so
// that each source retains its own entry in the results.
//
// It returns the deduplicated packages (in inventorySort order) and a map from
// every removed package pointer to the package pointer that replaced it, so
// vulnerability references can be rewritten onto the surviving package.
func mergeDuplicatePackages(pkgs []*extractor.Package) ([]*extractor.Package, map[*extractor.Package]*extractor.Package) {
	slices.SortFunc(pkgs, inventorySort)

	replacements := make(map[*extractor.Package]*extractor.Package)
	merged := make([]*extractor.Package, 0, len(pkgs))

	if len(pkgs) == 0 {
		return merged, replacements
	}

	kept := pkgs[0]
	merged = append(merged, kept)

	for i := 1; i < len(pkgs); i++ {
		current := pkgs[i]
		if inventorySort(kept, current) == 0 {
			replacements[current] = kept
		} else {
			kept = current
			merged = append(merged, kept)
		}
	}

	return merged, replacements
}
