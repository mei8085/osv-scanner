package output

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func Test_groupFixedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []models.VulnerabilityFlattened
		want testutility.Snapshot
	}{
		{
			name: "",
			args: testutility.LoadJSONFixture[[]models.VulnerabilityFlattened](t, "testdata/flattened_vulns.json"),
			want: testutility.NewSnapshot(),
		},
		{
			name: "",
			args: testutility.LoadJSONFixtureWithWindowsReplacements[[]models.VulnerabilityFlattened](t,
				"testdata/flattened_vulns.json",
				map[string]string{
					"/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/scorecard-check-osv-e2e/go.mod":                      "D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod",
				},
			),
			want: testutility.NewSnapshot().WithWindowsReplacements(
				map[string]string{
					"D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\sub-rust-project\\\\Cargo.lock": "/path/to/scorecard-check-osv-e2e/sub-rust-project/Cargo.lock",
					"D:\\\\path\\\\to\\\\scorecard-check-osv-e2e\\\\go.mod":                         "/path/to/scorecard-check-osv-e2e/go.mod",
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := groupFixedVersions(tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}

func Test_groupSARIFFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args models.VulnerabilityResults
		want testutility.Snapshot
	}{
		{
			args: testutility.LoadJSONFixtureWithWindowsReplacements[models.VulnerabilityResults](t,
				"testdata/test-vuln-results-a.json",
				map[string]string{
					"/path/to/sub-rust-project/Cargo.lock": "D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock",
					"/path/to/go.mod":                      "D:\\\\path\\\\to\\\\go.mod",
				},
			),
			want: testutility.NewSnapshot().WithWindowsReplacements(
				map[string]string{
					"D:\\\\path\\\\to\\\\sub-rust-project\\\\Cargo.lock": "/path/to/sub-rust-project/Cargo.lock",
					"D:\\\\path\\\\to\\\\go.mod":                         "/path/to/go.mod",
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := groupSARIFFindings(&tt.args)
			tt.want.MatchJSON(t, got)
		})
	}
}

func Test_groupSARIFFindings_Merging(t *testing.T) {
	t.Parallel()

	source := models.SourceInfo{Path: "/path/to/lockfile", Type: models.SourceTypeProjectPackage}

	pkgVulns := func(name, version string, vulns ...*osvschema.Vulnerability) models.PackageVulns {
		return models.PackageVulns{
			Package:         models.PackageInfo{Name: name, Version: version, Ecosystem: "npm"},
			Vulnerabilities: vulns,
		}
	}

	type groupSummary struct {
		DisplayID     string
		AliasedIDList []string
		Packages      []string
	}

	tests := []struct {
		name     string
		packages []models.PackageVulns
		want     []groupSummary
	}{
		{
			name: "packages_sharing_only_an_alias_are_merged",
			packages: []models.PackageVulns{
				pkgVulns("pkg-a", "1.0.0", &osvschema.Vulnerability{Id: "GHSA-1", Aliases: []string{"CVE-1"}}),
				pkgVulns("pkg-b", "1.0.0", &osvschema.Vulnerability{Id: "GO-1", Aliases: []string{"CVE-1"}}),
			},
			want: []groupSummary{
				{DisplayID: "CVE-1", AliasedIDList: []string{"CVE-1", "GO-1", "GHSA-1"}, Packages: []string{"pkg-a@1.0.0", "pkg-b@1.0.0"}},
			},
		},
		{
			name: "package_bridging_two_groups_merges_them",
			packages: []models.PackageVulns{
				pkgVulns("pkg-a", "1.0.0", &osvschema.Vulnerability{Id: "GHSA-1"}),
				pkgVulns("pkg-b", "1.0.0", &osvschema.Vulnerability{Id: "GO-1"}),
				pkgVulns("pkg-c", "1.0.0", &osvschema.Vulnerability{Id: "OSV-3", Aliases: []string{"GHSA-1", "GO-1"}}),
			},
			want: []groupSummary{
				{DisplayID: "GO-1", AliasedIDList: []string{"GO-1", "OSV-3", "GHSA-1"}, Packages: []string{"pkg-a@1.0.0", "pkg-b@1.0.0", "pkg-c@1.0.0"}},
			},
		},
		{
			name: "distinct_versions_and_unrelated_groups_are_kept",
			packages: []models.PackageVulns{
				pkgVulns("pkg-a", "1.2.3", &osvschema.Vulnerability{Id: "OSV-2"}),
				pkgVulns("pkg-a", "1.2.2", &osvschema.Vulnerability{Id: "OSV-2"}),
				pkgVulns("pkg-b", "1.0.0", &osvschema.Vulnerability{Id: "OSV-1"}),
			},
			want: []groupSummary{
				{DisplayID: "OSV-1", AliasedIDList: []string{"OSV-1"}, Packages: []string{"pkg-b@1.0.0"}},
				{DisplayID: "OSV-2", AliasedIDList: []string{"OSV-2"}, Packages: []string{"pkg-a@1.2.2", "pkg-a@1.2.3"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			groups := groupSARIFFindings(&models.VulnerabilityResults{
				Results: []models.PackageSource{{Source: source, Packages: tt.packages}},
			})

			got := make([]groupSummary, 0, len(groups))
			for _, g := range groups {
				summary := groupSummary{DisplayID: g.DisplayID, AliasedIDList: g.AliasedIDList}
				for _, pws := range g.PkgSource.StableKeys() {
					summary.Packages = append(summary.Packages, pws.Package.Name+"@"+pws.Package.Version)
				}
				got = append(got, summary)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("groupSARIFFindings() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_groupSARIFFindings_CrossSource ensures an event that is reported by
// several sources, possibly with differing amounts of detail, still forms one
// rule whose records and packages are all accounted for, and whose content does
// not depend on the order the sources are listed in.
func Test_groupSARIFFindings_CrossSource(t *testing.T) {
	t.Parallel()

	type groupSummary struct {
		DisplayID     string
		AliasedIDList []string
		Packages      []string
	}

	sourceA := models.SourceInfo{Path: "/path/to/lockfile", Type: models.SourceTypeProjectPackage}
	sourceB := models.SourceInfo{Path: "/path/to/sbom.cdx.json", Type: models.SourceTypeSBOM}

	pkg := func(name, version, id, summary string, aliases ...string) models.PackageVulns {
		return models.PackageVulns{
			Package: models.PackageInfo{Name: name, Version: version, Ecosystem: "npm"},
			Vulnerabilities: []*osvschema.Vulnerability{{
				Id:      id,
				Summary: summary,
				Aliases: aliases,
			}},
		}
	}

	// the same advisory, reported by a lockfile with full detail and by an SBOM
	// with none; plus a distinct vulnerability only the SBOM reports
	detailed := pkg("pkg-a", "1.0.0", "OSV-1", "scary!", "CVE-1")
	sparse := pkg("pkg-a", "1.0.0", "OSV-1", "")
	distinct := pkg("pkg-b", "1.0.0", "OSV-2", "also scary!", "CVE-2")

	build := func(results []models.PackageSource) []groupSummary {
		groups := groupSARIFFindings(&models.VulnerabilityResults{Results: results})

		summaries := make([]groupSummary, 0, len(groups))
		for _, g := range groups {
			summary := groupSummary{DisplayID: g.DisplayID, AliasedIDList: g.AliasedIDList}
			for _, pws := range g.PkgSource.StableKeys() {
				summary.Packages = append(summary.Packages, pws.Package.Name+"@"+pws.Package.Version)
			}
			summaries = append(summaries, summary)
		}

		return summaries
	}

	forward := build([]models.PackageSource{
		{Source: sourceA, Packages: []models.PackageVulns{detailed}},
		{Source: sourceB, Packages: []models.PackageVulns{sparse, distinct}},
	})
	reversed := build([]models.PackageSource{
		{Source: sourceB, Packages: []models.PackageVulns{distinct, sparse}},
		{Source: sourceA, Packages: []models.PackageVulns{detailed}},
	})

	want := []groupSummary{
		// the same package in two different sources stays traceable to both
		{DisplayID: "CVE-1", AliasedIDList: []string{"CVE-1", "OSV-1"}, Packages: []string{"pkg-a@1.0.0", "pkg-a@1.0.0"}},
		{DisplayID: "CVE-2", AliasedIDList: []string{"CVE-2", "OSV-2"}, Packages: []string{"pkg-b@1.0.0"}},
	}

	if diff := cmp.Diff(want, forward); diff != "" {
		t.Errorf("groupSARIFFindings() mismatch for cross-source records (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(forward, reversed); diff != "" {
		t.Errorf("groupSARIFFindings() must not depend on source order (-forward +reversed):\n%s", diff)
	}

	// the more detailed record is the one kept for the shared ID
	groups := groupSARIFFindings(&models.VulnerabilityResults{Results: []models.PackageSource{
		{Source: sourceA, Packages: []models.PackageVulns{detailed}},
		{Source: sourceB, Packages: []models.PackageVulns{sparse, distinct}},
	}})
	if got := groups[0].AliasedVulns["OSV-1"].GetSummary(); got != "scary!" {
		t.Errorf("expected the detailed record to be kept, got summary %q", got)
	}
}
