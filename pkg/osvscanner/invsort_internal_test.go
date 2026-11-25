package osvscanner

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// pkgAt builds a package at the given lockfile location with the given
// PURL type (which determines its OSV ecosystem), name and version.
func pkgAt(purlType, name, version, location string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purlType,
		Location: extractor.LocationFromPath(location),
	}
}

func osvVuln(id string) *osvschema.Vulnerability {
	return &osvschema.Vulnerability{Id: id}
}

func TestMergeDuplicatePackages_keepsPackagesFromDifferentEcosystems(t *testing.T) {
	t.Parallel()

	// Two dependencies with the same name and version reported from the same
	// lockfile location but belonging to different ecosystems. Name and
	// version alone cannot tell them apart; the ecosystem coordinate must keep
	// them as distinct packages.
	npmPkg := pkgAt(purl.TypeNPM, "shared-name", "1.2.3", "multi/lockfile")
	pypiPkg := pkgAt(purl.TypePyPi, "shared-name", "1.2.3", "multi/lockfile")

	merged, replacements := mergeDuplicatePackages([]*extractor.Package{npmPkg, pypiPkg})

	if len(merged) != 2 {
		t.Fatalf("expected both ecosystem packages to be kept, got %d packages: %v", len(merged), merged)
	}

	if len(replacements) != 0 {
		t.Fatalf("expected no package to be merged away, got replacements %v", replacements)
	}
}

func TestMergeDuplicatePackages_mergesSameCoordinatesAtSameLocation(t *testing.T) {
	t.Parallel()

	// The same dependency reported twice from the same lockfile (e.g. by two
	// extractors): identical location and ecosystem/name/version coordinates.
	first := pkgAt(purl.TypeNPM, "dupe", "2.0.0", "dir/lockfile")
	second := pkgAt(purl.TypeNPM, "dupe", "2.0.0", "dir/lockfile")

	merged, replacements := mergeDuplicatePackages([]*extractor.Package{first, second})

	if len(merged) != 1 {
		t.Fatalf("expected duplicate packages to be merged into one, got %d", len(merged))
	}

	if merged[0] != first {
		t.Errorf("expected the first package to be retained, got %v", merged[0])
	}

	if replacements[second] != first {
		t.Errorf("expected the removed package to map to the retained one, got %v", replacements[second])
	}
}

func TestMergeDuplicatePackages_keepsSourcesFromDifferentLockfiles(t *testing.T) {
	t.Parallel()

	// The same ecosystem/name/version dependency found in two different
	// lockfiles must stay separate so each source is preserved.
	fromA := pkgAt(purl.TypeNPM, "dep", "3.1.0", "project-a/lockfile")
	fromB := pkgAt(purl.TypeNPM, "dep", "3.1.0", "project-b/lockfile")

	merged, replacements := mergeDuplicatePackages([]*extractor.Package{fromA, fromB})

	if len(merged) != 2 {
		t.Fatalf("expected each lockfile source to be kept, got %d packages", len(merged))
	}

	if len(replacements) != 0 {
		t.Fatalf("expected no cross-lockfile merging, got replacements %v", replacements)
	}
}

func TestMergeDuplicatePackages_distinguishesVersions(t *testing.T) {
	t.Parallel()

	oldV := pkgAt(purl.TypeNPM, "lib", "1.0.0", "dir/lockfile")
	newV := pkgAt(purl.TypeNPM, "lib", "2.0.0", "dir/lockfile")

	merged, _ := mergeDuplicatePackages([]*extractor.Package{oldV, newV})

	if len(merged) != 2 {
		t.Fatalf("expected different versions to be kept separate, got %d packages", len(merged))
	}
}

func TestMergeDuplicatePackages_rewritesVulnerabilityPointers(t *testing.T) {
	t.Parallel()

	kept := pkgAt(purl.TypeNPM, "dupe", "2.0.0", "dir/lockfile")
	removed := pkgAt(purl.TypeNPM, "dupe", "2.0.0", "dir/lockfile")

	_, replacements := mergeDuplicatePackages([]*extractor.Package{kept, removed})

	vulns := []*inventory.PackageVuln{
		{Package: kept},
		{Package: removed},
	}

	// Mirror the pointer rewrite performed in scan(): only references to
	// merged-away packages are rewritten, and they land on the kept package.
	for _, vuln := range vulns {
		if replacement, ok := replacements[vuln.Package]; ok {
			vuln.Package = replacement
		}
	}

	for _, vuln := range vulns {
		if vuln.Package != kept {
			t.Errorf("expected vulnerability to reference the retained package, got %v", vuln.Package)
		}
	}
}

func TestMergeDuplicatePackages_empty(t *testing.T) {
	t.Parallel()

	merged, replacements := mergeDuplicatePackages(nil)

	if len(merged) != 0 {
		t.Errorf("expected no packages, got %d", len(merged))
	}

	if len(replacements) != 0 {
		t.Errorf("expected no replacements, got %v", replacements)
	}
}

func TestInventorySort_differentEcosystemsAreNotEqual(t *testing.T) {
	t.Parallel()

	// Regression test: packages sharing location/name/version but belonging to
	// different ecosystems must never compare equal, otherwise the merge step
	// treats them as one package and cross-ecosystem vulnerabilities leak.
	npmPkg := pkgAt(purl.TypeNPM, "shared-name", "1.2.3", "multi/lockfile")
	pypiPkg := pkgAt(purl.TypePyPi, "shared-name", "1.2.3", "multi/lockfile")

	if inventorySort(npmPkg, pypiPkg) == 0 {
		t.Errorf("packages from different ecosystems must not compare equal")
	}
}

// TestMergeDuplicatePackages_ecosystemFromMetadata covers packages whose
// ecosystem is carried in osvscannerjson metadata rather than derived from the
// PURL type (e.g. packages re-imported from osv-scanner JSON output). Two
// packages with identical name/version/location must still be separated by
// the ecosystem recorded in their metadata.
func TestMergeDuplicatePackages_ecosystemFromMetadata(t *testing.T) {
	t.Parallel()

	fromNpm := pkgAt(purl.TypeGeneric, "shared-name", "1.2.3", "imported/osv-scanner-custom.json")
	fromNpm.Metadata = &osvscannerjson.Metadata{Ecosystem: "npm"}
	fromPyPI := pkgAt(purl.TypeGeneric, "shared-name", "1.2.3", "imported/osv-scanner-custom.json")
	fromPyPI.Metadata = &osvscannerjson.Metadata{Ecosystem: "PyPI"}

	merged, replacements := mergeDuplicatePackages([]*extractor.Package{fromNpm, fromPyPI})

	if len(merged) != 2 {
		t.Fatalf("expected metadata-ecosystem packages to be kept separate, got %d packages", len(merged))
	}

	if len(replacements) != 0 {
		t.Fatalf("expected no merging across metadata ecosystems, got %v", replacements)
	}
}

// TestMergeDuplicatePackages_preservesPerEcosystemVulnerabilities is the
// end-to-end regression for the reported bug: when two ecosystems share a
// package name and version in the same lockfile, each package keeps its own
// vulnerability, and the other ecosystem's vulnerability is never attached.
func TestMergeDuplicatePackages_preservesPerEcosystemVulnerabilities(t *testing.T) {
	t.Parallel()

	npmPkg := pkgAt(purl.TypeNPM, "request", "2.88.0", "multi/lockfile")
	pypiPkg := pkgAt(purl.TypePyPi, "request", "2.88.0", "multi/lockfile")

	// The matchers attach vulnerabilities to the exact package pointer they
	// matched against, using ecosystem-aware queries.
	packageVulns := []*inventory.PackageVuln{
		{
			Package:       npmPkg,
			Vulnerability: osvVuln("GHSA-NPM-ONLY"),
		},
		{
			Package:       pypiPkg,
			Vulnerability: osvVuln("GHSA-PYPI-ONLY"),
		},
	}

	merged, replacements := mergeDuplicatePackages([]*extractor.Package{npmPkg, pypiPkg})
	if len(merged) != 2 {
		t.Fatalf("expected both ecosystem packages to survive the merge, got %d", len(merged))
	}

	for _, pv := range packageVulns {
		if replacement, ok := replacements[pv.Package]; ok {
			pv.Package = replacement
		}
	}

	vulnsByPkg := map[*extractor.Package]map[string]bool{}
	for _, pv := range packageVulns {
		if vulnsByPkg[pv.Package] == nil {
			vulnsByPkg[pv.Package] = map[string]bool{}
		}
		vulnsByPkg[pv.Package][pv.Vulnerability.GetId()] = true
	}

	if !vulnsByPkg[npmPkg]["GHSA-NPM-ONLY"] || vulnsByPkg[npmPkg]["GHSA-PYPI-ONLY"] {
		t.Errorf("npm package got wrong vulnerabilities: %v", vulnsByPkg[npmPkg])
	}

	if !vulnsByPkg[pypiPkg]["GHSA-PYPI-ONLY"] || vulnsByPkg[pypiPkg]["GHSA-NPM-ONLY"] {
		t.Errorf("pypi package got wrong vulnerabilities: %v", vulnsByPkg[pypiPkg])
	}
}
