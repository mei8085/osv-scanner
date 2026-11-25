package purl_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/utility/purl"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestGroupPackageByPURL_ShouldUnifyPackages(t *testing.T) {
	t.Parallel()
	input := []models.PackageSource{
		{
			Source: models.SourceInfo{
				Path: "/dir/lockfile.xml",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
					DepGroups: []string{"build"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(osvconstants.EcosystemMaven),
						Version:   "1.0.0",
					},
				},
			},
		},
		{
			Source: models.SourceInfo{
				Path: "/dir2/lockfile.json",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(osvconstants.EcosystemMaven),
					},
					Vulnerabilities: []*osvschema.Vulnerability{
						{Id: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
					DepGroups: []string{"test"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(osvconstants.EcosystemMaven),
						Version:   "1.0.0",
					},
				},
			},
		},
	}

	result, errors := purl.Group(input)

	expected := map[string]models.PackageVulns{
		"pkg:maven/foo.bar/the-first-package@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:the-first-package",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemMaven),
			},
			Vulnerabilities: []*osvschema.Vulnerability{
				{Id: "GHSA-456"},
			},
			Groups: []models.GroupInfo{
				{
					IDs:     []string{"GHSA-456"},
					Aliases: []string{"GHSA-456"},
				},
			},
			DepGroups: []string{"build", "test"},
		},
		"pkg:maven/foo.bar/package-2@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:package-2",
				Version:   "1.0.0",
				Ecosystem: string(osvconstants.EcosystemMaven),
			},
		},
	}

	if len(errors) > 0 {
		t.Errorf("Unexpected errors: %v", errors)
	}
	if len(result) != len(expected) {
		t.Errorf("Expected %d packages, got %d", len(expected), len(result))
	}
	for expectedPURL, expectedInfo := range expected {
		info, exists := result[expectedPURL]

		if !exists {
			t.Errorf("Expected package %s to be in the results", expectedPURL)
		}
		if !reflect.DeepEqual(info, expectedInfo) {
			t.Errorf("Expected package %s to be %v, got %v", expectedPURL, expectedInfo, info)
		}
	}
}

// TestGroup_keepsVulnerabilitiesFromEverySource ensures a package reported by
// several sources contributes every one of its records to the merged result,
// rather than the source that happens to be visited first winning outright.
func TestGroup_keepsVulnerabilitiesFromEverySource(t *testing.T) {
	t.Parallel()

	pkg := func(vulns ...*osvschema.Vulnerability) models.PackageVulns {
		return models.PackageVulns{
			Package: models.PackageInfo{
				Name:      "mine1",
				Version:   "1.2.3",
				Ecosystem: string(osvconstants.EcosystemNPM),
			},
			Vulnerabilities: vulns,
		}
	}

	// the same package seen from a lockfile and from an SBOM, each reporting a
	// different alias of the same security event, plus an independent vuln
	fromLockfile := pkg(
		&osvschema.Vulnerability{Id: "GHSA-aaaa", Aliases: []string{"CVE-1"}, Summary: "from the lockfile"},
		&osvschema.Vulnerability{Id: "OSV-9"},
	)
	fromSBOM := pkg(
		&osvschema.Vulnerability{Id: "PYSEC-1", Aliases: []string{"CVE-1"}},
	)

	result, errs := purl.Group([]models.PackageSource{
		{Packages: []models.PackageVulns{fromLockfile}},
		{Packages: []models.PackageVulns{fromSBOM}},
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	merged, ok := result["pkg:npm/mine1@1.2.3"]
	if !ok {
		t.Fatalf("expected the package in the result, got %v", result)
	}

	gotVulnIDs := make([]string, 0, len(merged.Vulnerabilities))
	for _, vuln := range merged.Vulnerabilities {
		gotVulnIDs = append(gotVulnIDs, vuln.GetId())
	}
	slices.Sort(gotVulnIDs)

	if diff := cmp.Diff([]string{"GHSA-aaaa", "OSV-9", "PYSEC-1"}, gotVulnIDs); diff != "" {
		t.Errorf("expected every source's records to be kept (-want +got):\n%s", diff)
	}

	// the aliases of the event are merged into one group, and the independent
	// vulnerability keeps its own
	wantGroups := []models.GroupInfo{
		{IDs: []string{"OSV-9"}, Aliases: []string{"OSV-9"}},
		{IDs: []string{"PYSEC-1", "GHSA-aaaa"}, Aliases: []string{"CVE-1", "GHSA-aaaa", "PYSEC-1"}},
	}
	if diff := cmp.Diff(wantGroups, merged.Groups); diff != "" {
		t.Errorf("unexpected merged groups (-want +got):\n%s", diff)
	}

	// reversing the source order must not change the merged result
	reversed, _ := purl.Group([]models.PackageSource{
		{Packages: []models.PackageVulns{fromSBOM}},
		{Packages: []models.PackageVulns{fromLockfile}},
	})

	reversedMerged := reversed["pkg:npm/mine1@1.2.3"]

	reversedVulnIDs := make([]string, 0, len(reversedMerged.Vulnerabilities))
	for _, vuln := range reversedMerged.Vulnerabilities {
		reversedVulnIDs = append(reversedVulnIDs, vuln.GetId())
	}
	slices.Sort(reversedVulnIDs)

	if diff := cmp.Diff(gotVulnIDs, reversedVulnIDs); diff != "" {
		t.Errorf("merging must not depend on the source order (-forward +reversed):\n%s", diff)
	}
	if diff := cmp.Diff(wantGroups, reversedMerged.Groups); diff != "" {
		t.Errorf("merging must not depend on the source order (-forward +reversed):\n%s", diff)
	}
}
