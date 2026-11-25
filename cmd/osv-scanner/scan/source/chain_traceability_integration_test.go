package source_test

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// This file drives one dependency graph through the entire integration chain:
//
//	lockfile or SBOM extraction -> offline OSV zip matching ->
//	withdrawn/fix/semver decisions -> grouper/report merging -> JSON report.
//
// The same three npm packages are described by both a package-lock.json and a
// CycloneDX SBOM, matched against a hermetic OSV database built on disk.

const (
	traceChainEcosystem = "npm"

	traceChainFixedPkg  = "trace-chain-fixed"
	traceChainActivePkg = "trace-chain-active"
	traceChainWithPkg   = "trace-chain-withdrawn-control"

	traceChainBelowFixVersion = "1.9.0"
	traceChainFixVersion      = "1.10.0"
	traceChainWithPkgVersion  = "1.0.0"

	traceChainFixedVulnID     = "OSV-2026-TRACE-FIXED"
	traceChainActiveVulnID    = "OSV-2026-TRACE-ACTIVE"
	traceChainLiveVulnID      = "OSV-2026-TRACE-LIVE"
	traceChainWithdrawnVulnID = "OSV-2026-TRACE-WITHDRAWN"
	traceChainActiveAlias     = "CVE-2026-TRACE-ACT"
)

// traceChainFixture holds the hermetic inputs for the chain test.
type traceChainFixture struct {
	dbPath    string
	lockfile  string
	sbom      string
	beforeFix string
}

func setupTraceChainFixture(t *testing.T) traceChainFixture {
	t.Helper()

	root := t.TempDir()
	fx := traceChainFixture{
		dbPath:    filepath.Join(root, "local-db"),
		lockfile:  filepath.Join(root, "lock", "package-lock.json"),
		beforeFix: filepath.Join(root, "before-fix", "package-lock.json"),
		sbom:      filepath.Join(root, "sbom", "trace-chain.cdx.json"),
	}

	traceChainBuildDB(t, fx.dbPath)
	traceChainWriteFile(t, fx.lockfile, traceChainLockfileJSON(traceChainFixVersion))
	traceChainWriteFile(t, fx.beforeFix, traceChainLockfileJSON(traceChainBelowFixVersion))
	traceChainWriteFile(t, fx.sbom, traceChainSBOMJSON())

	return fx
}

func traceChainWriteFile(t *testing.T, path, contents string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("creating directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// traceChainBuildDB writes <dbPath>/osv-scalibr/npm/all.zip, which is exactly
// the on-disk layout the offline ("osvlocal") matcher reads without downloading.
func traceChainBuildDB(t *testing.T, dbPath string) {
	t.Helper()

	ecoDir := filepath.Join(dbPath, "osv-scalibr", traceChainEcosystem)
	if err := os.MkdirAll(ecoDir, 0o750); err != nil {
		t.Fatalf("creating offline db directory: %v", err)
	}

	records := map[string]string{
		traceChainActiveVulnID + ".json":    traceChainActiveAdvisory(),
		traceChainFixedVulnID + ".json":     traceChainFixedAdvisory(),
		traceChainLiveVulnID + ".json":      traceChainLiveAdvisory(),
		traceChainWithdrawnVulnID + ".json": traceChainWithdrawnAdvisory(),
		// An unparseable record must be skipped without taking the other
		// valid advisories (or the whole database) down with it.
		"OSV-2026-TRACE-CORRUPT.json": `{"id": 123, "affected": [`,
	}

	zipPath := filepath.Join(ecoDir, "all.zip")
	if err := traceChainWriteZip(zipPath, records); err != nil {
		t.Fatalf("writing offline db zip: %v", err)
	}
}

func traceChainWriteZip(path string, files map[string]string) error {
	zf, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = zf.Close() }()

	zw := zip.NewWriter(zf)
	for name, contents := range files {
		w, err := zw.Create(name)
		if err != nil {
			_ = zw.Close()

			return err
		}
		if _, err := w.Write([]byte(contents)); err != nil {
			_ = zw.Close()

			return err
		}
	}

	return zw.Close()
}

// traceChainLockfileJSON is an npm v1 lockfile. fixedPkgVersion controls
// whether trace-chain-fixed sits on or before its fix boundary.
func traceChainLockfileJSON(fixedPkgVersion string) string {
	return fmt.Sprintf(`{
  "requires": true,
  "lockfileVersion": 1,
  "dependencies": {
    %[1]q: {"version": %[2]q},
    %[3]q: {"version": "1.9.0"},
    %[4]q: {"version": "1.0.0"}
  }
}
`, traceChainFixedPkg, fixedPkgVersion, traceChainActivePkg, traceChainWithPkg)
}

// traceChainSBOMJSON describes the exact same packages as the lockfile.
func traceChainSBOMJSON() string {
	return fmt.Sprintf(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": %[1]q,
      "version": "1.9.0",
      "purl": "pkg:npm/%[1]s@1.9.0"
    },
    {
      "type": "library",
      "name": %[2]q,
      "version": %[3]q,
      "purl": "pkg:npm/%[2]s@%[3]s"
    },
    {
      "type": "library",
      "name": %[4]q,
      "version": "1.0.0",
      "purl": "pkg:npm/%[4]s@1.0.0"
    }
  ]
}
`, traceChainActivePkg, traceChainFixedPkg, traceChainFixVersion, traceChainWithPkg)
}

// traceChainActiveAdvisory fixes at 1.10.0. Installed 1.9.0 is affected under
// semver numeric ordering (1.9.0 < 1.10.0 even though a lexical compare of the
// minor components would get it wrong).
func traceChainActiveAdvisory() string {
	return fmt.Sprintf(`{
  "schema_version": "1.7.0",
  "id": %[1]q,
  "modified": "2026-01-01T00:00:00Z",
  "aliases": [%[2]q],
  "affected": [{
    "package": {"name": %[3]q, "ecosystem": "npm", "purl": "pkg:npm/%[3]s"},
    "ranges": [{
      "type": "SEMVER",
      "events": [{"introduced": "0"}, {"fixed": %[4]q}]
    }]
  }]
}
`, traceChainActiveVulnID, traceChainActiveAlias, traceChainActivePkg, traceChainFixVersion)
}

// traceChainFixedAdvisory has the same fix boundary as the active advisory but
// targets trace-chain-fixed.
func traceChainFixedAdvisory() string {
	return fmt.Sprintf(`{
  "schema_version": "1.7.0",
  "id": %[1]q,
  "modified": "2026-01-01T00:00:00Z",
  "affected": [{
    "package": {"name": %[2]q, "ecosystem": "npm", "purl": "pkg:npm/%[2]s"},
    "ranges": [{
      "type": "SEMVER",
      "events": [{"introduced": "0"}, {"fixed": %[3]q}]
    }]
  }]
}
`, traceChainFixedVulnID, traceChainFixedPkg, traceChainFixVersion)
}

// traceChainLiveAdvisory affects every version of the withdrawn-control
// package and stays valid.
func traceChainLiveAdvisory() string {
	return fmt.Sprintf(`{
  "schema_version": "1.7.0",
  "id": %[1]q,
  "modified": "2026-01-01T00:00:00Z",
  "affected": [{
    "package": {"name": %[2]q, "ecosystem": "npm", "purl": "pkg:npm/%[2]s"},
    "ranges": [{
      "type": "SEMVER",
      "events": [{"introduced": "0"}]
    }]
  }]
}
`, traceChainLiveVulnID, traceChainWithPkg)
}

// traceChainWithdrawnAdvisory is identical in reach to the live advisory but
// withdrawn, so the offline matcher must drop it.
func traceChainWithdrawnAdvisory() string {
	return fmt.Sprintf(`{
  "schema_version": "1.7.0",
  "id": %[1]q,
  "modified": "2026-01-01T00:00:00Z",
  "withdrawn": "2026-02-01T00:00:00Z",
  "affected": [{
    "package": {"name": %[2]q, "ecosystem": "npm", "purl": "pkg:npm/%[2]s"},
    "ranges": [{
      "type": "SEMVER",
      "events": [{"introduced": "0"}]
    }]
  }]
}
`, traceChainWithdrawnVulnID, traceChainWithPkg)
}

// traceChainRun executes the source command fully offline and decodes the JSON
// report into the typed result model.
func traceChainRun(t *testing.T, extraArgs ...string) models.VulnerabilityResults {
	t.Helper()

	args := make([]string, 0, 6+len(extraArgs))
	args = append(args, "", "source", "--format", "json", "--all-packages", "--offline")
	args = append(args, extraArgs...)

	tc := testcmd.Case{
		Args:         args,
		Exit:         1, // the active/live advisories guarantee a failing exit code
		CassetteName: testcmd.NoInteractions,
	}

	stdout, stderr := testcmd.RunAndNormalize(t, tc)

	var res models.VulnerabilityResults
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("decoding JSON report: %v\n--- stdout ---\n%s\n--- stderr ---\n%s", err, stdout, stderr)
	}

	return res
}

func traceChainIndexPackages(t *testing.T, res models.VulnerabilityResults) map[string]*models.PackageVulns {
	t.Helper()

	indexed := map[string]*models.PackageVulns{}
	for ri := range res.Results {
		for pi := range res.Results[ri].Packages {
			pv := &res.Results[ri].Packages[pi]
			key := pv.Package.Name + "@" + pv.Package.Version
			if _, dup := indexed[key]; dup {
				t.Errorf("package %s appears more than once in the report", key)
			}
			indexed[key] = pv
		}
	}

	return indexed
}

func traceChainRequirePackage(
	t *testing.T,
	indexed map[string]*models.PackageVulns,
	key string,
	label string,
) *models.PackageVulns {
	t.Helper()

	pv, ok := indexed[key]
	if !ok {
		keys := make([]string, 0, len(indexed))
		for k := range indexed {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		t.Fatalf("%s: expected package %q in report, got packages %v", label, key, keys)
	}

	return pv
}

func traceChainFixedEvents(v *osvschema.Vulnerability) []string {
	var fixed []string
	for _, affected := range v.GetAffected() {
		for _, r := range affected.GetRanges() {
			for _, event := range r.GetEvents() {
				if version := event.GetFixed(); version != "" {
					fixed = append(fixed, version)
				}
			}
		}
	}

	return fixed
}

func traceChainIntroducedEvents(v *osvschema.Vulnerability) []string {
	var introduced []string
	for _, affected := range v.GetAffected() {
		for _, r := range affected.GetRanges() {
			for _, event := range r.GetEvents() {
				if version := event.GetIntroduced(); version != "" {
					introduced = append(introduced, version)
				}
			}
		}
	}

	return introduced
}

func traceChainGroupContainsID(groups []models.GroupInfo, vulnID string) bool {
	for _, group := range groups {
		if slices.Contains(group.IDs, vulnID) {
			return true
		}
	}

	return false
}

// traceChainProfile is the source-independent risk signature used to compare
// the lockfile and SBOM runs.
type traceChainProfile struct {
	VulnIDs     map[string][]string
	FixedBounds map[string][]string
}

func traceChainBuildProfile(res models.VulnerabilityResults) traceChainProfile {
	profile := traceChainProfile{
		VulnIDs:     map[string][]string{},
		FixedBounds: map[string][]string{},
	}

	for _, source := range res.Results {
		for _, pv := range source.Packages {
			key := pv.Package.Name + "@" + pv.Package.Version

			ids := make([]string, 0, len(pv.Vulnerabilities))
			fixed := make([]string, 0, len(pv.Vulnerabilities))
			for _, v := range pv.Vulnerabilities {
				ids = append(ids, v.GetId())
				fixed = append(fixed, traceChainFixedEvents(v)...)
			}
			slices.Sort(ids)
			slices.Sort(fixed)

			profile.VulnIDs[key] = ids
			profile.FixedBounds[key] = slices.Compact(fixed)
		}
	}

	return profile
}

// traceChainAssertRiskReport validates the package -> vulnerability -> fix
// boundary -> group traceability that must hold for either input source.
func traceChainAssertRiskReport(
	t *testing.T,
	res models.VulnerabilityResults,
	label string,
) traceChainProfile {
	t.Helper()

	indexed := traceChainIndexPackages(t, res)

	fixedKey := traceChainFixedPkg + "@" + traceChainFixVersion
	activeKey := traceChainActivePkg + "@" + traceChainBelowFixVersion
	withKey := traceChainWithPkg + "@" + traceChainWithPkgVersion

	fixedPkg := traceChainRequirePackage(t, indexed, fixedKey, label)
	activePkg := traceChainRequirePackage(t, indexed, activeKey, label)
	withPkg := traceChainRequirePackage(t, indexed, withKey, label)

	for _, pv := range []*models.PackageVulns{fixedPkg, activePkg, withPkg} {
		if pv.Package.Ecosystem != traceChainEcosystem {
			t.Errorf("%s: package %s has ecosystem %q, want %q",
				label, pv.Package.Name, pv.Package.Ecosystem, traceChainEcosystem)
		}
	}

	// Fix information: at exactly the fixed version the package must be
	// inventoried (--all-packages) but carry no alert and no group.
	if len(fixedPkg.Vulnerabilities) != 0 {
		ids := make([]string, 0, len(fixedPkg.Vulnerabilities))
		for _, v := range fixedPkg.Vulnerabilities {
			ids = append(ids, v.GetId())
		}
		t.Errorf("%s: already-fixed package %s must not re-alert, got vulnerabilities %v",
			label, fixedKey, ids)
	}
	if len(fixedPkg.Groups) != 0 {
		t.Errorf("%s: already-fixed package %s should have no report groups, got %+v",
			label, fixedKey, fixedPkg.Groups)
	}

	// Semantic versioning + fix boundary: 1.9.0 < 1.10.0, so the active
	// advisory is valid and must remain visible.
	if len(activePkg.Vulnerabilities) != 1 {
		t.Fatalf("%s: %s must report exactly %s, got %d vulnerabilities",
			label, activeKey, traceChainActiveVulnID, len(activePkg.Vulnerabilities))
	}
	activeVuln := activePkg.Vulnerabilities[0]
	if activeVuln.GetId() != traceChainActiveVulnID {
		t.Fatalf("%s: %s reports %q, want %q",
			label, activeKey, activeVuln.GetId(), traceChainActiveVulnID)
	}
	if !slices.Contains(activeVuln.GetAliases(), traceChainActiveAlias) {
		t.Errorf("%s: %s is missing alias %s in report",
			label, traceChainActiveVulnID, traceChainActiveAlias)
	}
	if !slices.Contains(traceChainIntroducedEvents(activeVuln), "0") {
		t.Errorf("%s: %s lost its introduced boundary", label, traceChainActiveVulnID)
	}
	if fixed := traceChainFixedEvents(activeVuln); !slices.Contains(fixed, traceChainFixVersion) {
		t.Errorf("%s: %s lost its fix boundary %q, got %v",
			label, traceChainActiveVulnID, traceChainFixVersion, fixed)
	}

	// Report merging must keep the vulnerability reachable through a group.
	if len(activePkg.Groups) != 1 {
		t.Fatalf("%s: %s should have exactly one group, got %d",
			label, activeKey, len(activePkg.Groups))
	}
	if !slices.Contains(activePkg.Groups[0].IDs, traceChainActiveVulnID) {
		t.Errorf("%s: merged group %+v does not contain %s",
			label, activePkg.Groups[0], traceChainActiveVulnID)
	}
	if !slices.Contains(activePkg.Groups[0].Aliases, traceChainActiveAlias) {
		t.Errorf("%s: merged group %+v does not retain alias %s",
			label, activePkg.Groups[0], traceChainActiveAlias)
	}

	// Withdrawn status: the live twin survives while the withdrawn one does
	// not, proving withdrawal (not a failed range match) removes it.
	if len(withPkg.Vulnerabilities) != 1 {
		t.Fatalf("%s: %s must report exactly the live advisory, got %d vulnerabilities",
			label, withKey, len(withPkg.Vulnerabilities))
	}
	if id := withPkg.Vulnerabilities[0].GetId(); id != traceChainLiveVulnID {
		t.Errorf("%s: %s reports %q, want live advisory %q (withdrawn must be excluded)",
			label, withKey, id, traceChainLiveVulnID)
	}

	// Whole-report invariants: forbidden records never appear, and every
	// reported vulnerability stays linked to a merged group.
	reportedIDs := map[string]struct{}{}
	for key, pv := range indexed {
		for _, v := range pv.Vulnerabilities {
			id := v.GetId()
			reportedIDs[id] = struct{}{}
			if !traceChainGroupContainsID(pv.Groups, id) {
				t.Errorf("%s: vulnerability %s on %s is not traceable to any report group",
					label, id, key)
			}
		}
	}

	for _, banned := range []string{traceChainFixedVulnID, traceChainWithdrawnVulnID} {
		if _, ok := reportedIDs[banned]; ok {
			t.Errorf("%s: %s must not be reported", label, banned)
		}
	}
	for _, required := range []string{traceChainActiveVulnID, traceChainLiveVulnID} {
		if _, ok := reportedIDs[required]; !ok {
			t.Errorf("%s: valid vulnerability %s was masked by withdrawn/corrupt records",
				label, required)
		}
	}

	return traceChainBuildProfile(res)
}

// TestIntegration_LockfileAndSBOM_OfflineMatchGroupingTraceability runs the
// same dependency graph from a lockfile and from an SBOM and requires identical
// risk decisions with traceable package/vulnerability/fix relationships.
func TestIntegration_LockfileAndSBOM_OfflineMatchGroupingTraceability(t *testing.T) {
	t.Parallel()

	fx := setupTraceChainFixture(t)

	lockRes := traceChainRun(t, "--local-db-path", fx.dbPath, fx.lockfile)
	lockProfile := traceChainAssertRiskReport(t, lockRes, "lockfile")

	sbomRes := traceChainRun(t, "--local-db-path", fx.dbPath, "--sbom", fx.sbom)
	sbomProfile := traceChainAssertRiskReport(t, sbomRes, "sbom")

	if !reflect.DeepEqual(lockProfile, sbomProfile) {
		t.Errorf("lockfile and SBOM sources produced different risk profiles for the same dependencies\n"+
			"lockfile: %#v\nSBOM:     %#v", lockProfile, sbomProfile)
	}
}

// TestIntegration_FixBoundary_VersionSemanticsFlipRisk is the positive control
// for the fix boundary: before the fixed version the advisory alerts, while at
// the fixed version (exercised in the parity test) it is silent.
func TestIntegration_FixBoundary_VersionSemanticsFlipRisk(t *testing.T) {
	t.Parallel()

	fx := setupTraceChainFixture(t)
	res := traceChainRun(t, "--local-db-path", fx.dbPath, fx.beforeFix)

	indexed := traceChainIndexPackages(t, res)
	key := traceChainFixedPkg + "@" + traceChainBelowFixVersion
	pv := traceChainRequirePackage(t, indexed, key, "before-fix-lockfile")

	if len(pv.Vulnerabilities) != 1 {
		t.Fatalf("pre-fix %s must alert %s, got %d vulnerabilities",
			key, traceChainFixedVulnID, len(pv.Vulnerabilities))
	}
	v := pv.Vulnerabilities[0]
	if v.GetId() != traceChainFixedVulnID {
		t.Fatalf("pre-fix %s reports %q, want %q", key, v.GetId(), traceChainFixedVulnID)
	}
	if !slices.Contains(traceChainFixedEvents(v), traceChainFixVersion) {
		t.Errorf("pre-fix report for %s does not retain fix boundary %s",
			traceChainFixedVulnID, traceChainFixVersion)
	}
	if !traceChainGroupContainsID(pv.Groups, traceChainFixedVulnID) {
		t.Errorf("pre-fix %s is not traceable to a report group", traceChainFixedVulnID)
	}
}
