package output_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/grouper"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestPrintOutputResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestBuildResults_ExactEcosystemGrouping(t *testing.T) {
	t.Parallel()

	packageWithVuln := func(name, ecosystem, vulnID string) models.PackageVulns {
		return models.PackageVulns{
			Package: models.PackageInfo{
				Name:      name,
				Version:   "1.0.0",
				Ecosystem: ecosystem,
			},
			Vulnerabilities: []*osvschema.Vulnerability{{Id: vulnID}},
			Groups:          []models.GroupInfo{{IDs: []string{vulnID}}},
		}
	}

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Source: models.SourceInfo{Path: "mixed.sbom", Type: models.SourceTypeSBOM},
			Packages: []models.PackageVulns{
				packageWithVuln("base-package", "Alpine", "OSV-BASE"),
				packageWithVuln("versioned-package", "Alpine:v3.18", "OSV-VERSIONED"),
			},
		}},
	}

	got := make(map[string][]string)
	for _, ecosystem := range output.BuildResults(vulnResult).Ecosystems {
		for _, source := range ecosystem.Sources {
			for _, pkg := range source.Packages {
				got[ecosystem.Name] = append(got[ecosystem.Name], pkg.Name)
			}
		}
	}
	want := map[string][]string{
		"Alpine":       {"base-package"},
		"Alpine:v3.18": {"versioned-package"},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("BuildResults() ecosystem packages mismatch (-want +got):\n%s", diff)
	}
}

// TestBuildResults_GroupAggregation ensures that a security event reported by
// multiple sources, under different but cross-referenced IDs, is reported as
// one group whose identity, severity and remediation are stable regardless of
// the order the reports arrive in.
func TestBuildResults_GroupAggregation(t *testing.T) {
	t.Parallel()

	// two records describing the same event, plus one unrelated record
	recordA := func() *osvschema.Vulnerability {
		return &osvschema.Vulnerability{
			Id:      "OSV-1",
			Summary: "Something scary!",
			Severity: []*osvschema.Severity{{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
			}},
			Affected: []*osvschema.Affected{{
				Package: &osvschema.Package{Name: "mine1", Ecosystem: "npm"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_SEMVER,
					Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.2.4"}},
				}},
			}},
		}
	}
	recordB := func() *osvschema.Vulnerability {
		return &osvschema.Vulnerability{
			Id:      "GHSA-123",
			Aliases: []string{"OSV-1"},
			Summary: "Something scary!",
			Severity: []*osvschema.Severity{{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
			}},
			// this alias reports a later fix, which must win as it resolves the
			// whole event
			Affected: []*osvschema.Affected{{
				Package: &osvschema.Package{Name: "mine1", Ecosystem: "npm"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_SEMVER,
					Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.3.0"}},
				}},
			}},
		}
	}
	unrelated := func() *osvschema.Vulnerability {
		return &osvschema.Vulnerability{Id: "OSV-9", Summary: "Something else"}
	}

	build := func(vulns ...*osvschema.Vulnerability) models.VulnerabilityResults {
		pkg := models.PackageVulns{
			Package:         models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
			Vulnerabilities: vulns,
		}

		// Build the groups against the package so severities are resolved too
		pkg.Groups = grouper.Build(pkg, false)

		return models.VulnerabilityResults{
			Results: []models.PackageSource{{
				Source:   models.SourceInfo{Path: "package-lock.json", Type: models.SourceTypeProjectPackage},
				Packages: []models.PackageVulns{pkg},
			}},
		}
	}

	collect := func(results models.VulnerabilityResults) []output.VulnResult {
		var vulns []output.VulnResult
		for _, ecosystem := range output.BuildResults(&results).Ecosystems {
			for _, source := range ecosystem.Sources {
				for _, pkg := range source.Packages {
					vulns = append(vulns, pkg.RegularVulns...)
				}
			}
		}

		return vulns
	}

	want := collect(build(recordA(), recordB(), unrelated()))

	// the order the records were reported in must not change the report
	for _, vulns := range [][]*osvschema.Vulnerability{
		{recordB(), recordA(), unrelated()},
		{unrelated(), recordB(), recordA()},
		{recordA(), unrelated(), recordB()},
	} {
		if diff := cmp.Diff(want, collect(build(vulns...))); diff != "" {
			t.Errorf("BuildResults() is not order independent (-want +got):\n%s", diff)
		}
	}

	if len(want) != 2 {
		t.Fatalf("expected the unrelated record to stay in its own group, got %+v", want)
	}

	// the related records form one group, whose representative is the
	// preferred identifier and which carries the highest severity and the
	// highest fix of any of its records
	event := want[0]
	if event.ID != "OSV-1" {
		t.Errorf("expected representative ID OSV-1, got %q", event.ID)
	}
	if diff := cmp.Diff([]string{"OSV-1", "GHSA-123"}, event.GroupIDs); diff != "" {
		t.Errorf("unexpected group IDs (-want +got):\n%s", diff)
	}
	if event.SeverityScore != "8.3" {
		t.Errorf("expected aggregated max severity 8.3, got %q", event.SeverityScore)
	}
	if !event.IsFixable || event.FixedVersion != "1.3.0" {
		t.Errorf("expected the event to be fixed at 1.3.0, got fixable=%v version=%q", event.IsFixable, event.FixedVersion)
	}
	if event.Description != "Something scary!" {
		t.Errorf("expected the event's description to be aggregated, got %q", event.Description)
	}

	// the unrelated record keeps its own identity and is not affected by the
	// event's aggregation
	if unrelated := want[1]; unrelated.ID != "OSV-9" || len(unrelated.GroupIDs) != 1 {
		t.Errorf("expected the unrelated record to stay separate, got %+v", unrelated)
	}
}

// TestBuildResults_GroupAggregation_MissingFix ensures a group is not reported
// as fixed just because one of its records has a fix that does not apply to the
// installed package.
func TestBuildResults_GroupAggregation_MissingFix(t *testing.T) {
	t.Parallel()

	vulns := []*osvschema.Vulnerability{
		{Id: "OSV-1", Summary: "Fixable"},
		{
			Id:      "GHSA-123",
			Aliases: []string{"OSV-1"},
			// only fixed for a different package, so it cannot resolve the event
			Affected: []*osvschema.Affected{{
				Package: &osvschema.Package{Name: "other", Ecosystem: "npm"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_SEMVER,
					Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "9.9.9"}},
				}},
			}},
		},
	}

	pkg := models.PackageVulns{
		Package:         models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
		Vulnerabilities: vulns,
	}
	pkg.Groups = grouper.Build(pkg, false)

	results := models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Source:   models.SourceInfo{Path: "package-lock.json", Type: models.SourceTypeProjectPackage},
			Packages: []models.PackageVulns{pkg},
		}},
	}

	var vulnsOut []output.VulnResult
	for _, ecosystem := range output.BuildResults(&results).Ecosystems {
		for _, source := range ecosystem.Sources {
			for _, p := range source.Packages {
				vulnsOut = append(vulnsOut, p.RegularVulns...)
			}
		}
	}

	if len(vulnsOut) != 1 {
		t.Fatalf("expected one group, got %+v", vulnsOut)
	}
	if vulnsOut[0].IsFixable || vulnsOut[0].FixedVersion != output.UnfixedDescription {
		t.Errorf("expected the group to be unfixed, got fixable=%v version=%q",
			vulnsOut[0].IsFixable, vulnsOut[0].FixedVersion)
	}
}
