package models_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestGroupInfo_Canonicalize(t *testing.T) {
	t.Parallel()

	group := models.GroupInfo{
		IDs:     []string{"GHSA-aaaa", "PYSEC-1", "PYSEC-1"},
		Aliases: []string{"GHSA-aaaa", "CVE-1", "", "PYSEC-1", "CVE-1"},
	}

	got := group.Canonicalize()

	want := models.GroupInfo{
		IDs:     []string{"PYSEC-1", "GHSA-aaaa"},
		Aliases: []string{"CVE-1", "GHSA-aaaa", "PYSEC-1"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Canonicalize() returned an unexpected result (-want +got):\n%s", diff)
	}

	// the receiver must not be modified, so canonicalizing again is stable
	if diff := cmp.Diff(want, group.Canonicalize()); diff != "" {
		t.Errorf("Canonicalize() is not idempotent (-want +got):\n%s", diff)
	}
	if !slices.Equal(group.IDs, []string{"GHSA-aaaa", "PYSEC-1", "PYSEC-1"}) {
		t.Errorf("Canonicalize() modified the receiver's IDs: %v", group.IDs)
	}
}

func TestSortGroups(t *testing.T) {
	t.Parallel()

	groups := []models.GroupInfo{
		{IDs: []string{"GHSA-aaaa"}},
		{IDs: []string{"GO-2"}},
		{IDs: []string{"CVE-1"}},
		{IDs: []string{"GO-1"}},
	}

	models.SortGroups(groups)

	want := []models.GroupInfo{
		{IDs: []string{"CVE-1"}},
		{IDs: []string{"GO-1"}},
		{IDs: []string{"GO-2"}},
		{IDs: []string{"GHSA-aaaa"}},
	}
	if diff := cmp.Diff(want, groups); diff != "" {
		t.Errorf("SortGroups() returned an unexpected order (-want +got):\n%s", diff)
	}
}

func TestPackageVulns_MarshalJSON_isCanonical(t *testing.T) {
	t.Parallel()

	vuln := func(id string, aliases ...string) *osvschema.Vulnerability {
		return &osvschema.Vulnerability{Id: id, Aliases: aliases}
	}
	group := func(ids ...string) models.GroupInfo {
		return models.GroupInfo{IDs: ids, Aliases: ids}
	}

	// the same package reported with its records and groups in different
	// orders, as different sources might report it
	first := models.PackageVulns{
		Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
		Vulnerabilities: []*osvschema.Vulnerability{
			vuln("GHSA-aaaa", "CVE-1"),
			vuln("PYSEC-1", "CVE-1"),
		},
		Groups: []models.GroupInfo{
			group("PYSEC-1", "GHSA-aaaa"),
		},
	}
	second := models.PackageVulns{
		Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
		Vulnerabilities: []*osvschema.Vulnerability{
			vuln("PYSEC-1", "CVE-1"),
			vuln("GHSA-aaaa", "CVE-1"),
		},
		Groups: []models.GroupInfo{
			group("GHSA-aaaa", "PYSEC-1"),
		},
	}

	firstJSON, err := json.Marshal(&first)
	if err != nil {
		t.Fatal(err)
	}

	secondJSON, err := json.Marshal(&second)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(string(firstJSON), string(secondJSON)); diff != "" {
		t.Errorf("marshaling the same package in a different order gave different JSON (-first +second):\n%s", diff)
	}

	// marshaling must not modify the receiver, so it is repeatable
	firstAgain, err := json.Marshal(&first)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(firstJSON), string(firstAgain)); diff != "" {
		t.Errorf("marshaling is not repeatable (-first +second):\n%s", diff)
	}
	if first.Vulnerabilities[0].GetId() != "GHSA-aaaa" {
		t.Errorf("marshaling reordered the receiver's vulnerabilities: %v", first.Vulnerabilities)
	}
	if first.Groups[0].IDs[0] != "PYSEC-1" {
		t.Errorf("marshaling modified the receiver's groups: %v", first.Groups)
	}
}

func TestVulnerabilityResults_Flatten_ungroupedRecordIsStillReported(t *testing.T) {
	t.Parallel()

	vuln := &osvschema.Vulnerability{Id: "OSV-1"}
	results := models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Source: models.SourceInfo{Path: "package-lock.json"},
			Packages: []models.PackageVulns{{
				Package:         models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{vuln},
			}},
		}},
	}

	flattened := results.Flatten()

	if len(flattened) != 1 {
		t.Fatalf("expected the ungrouped record to be reported, got %d entries", len(flattened))
	}
	if flattened[0].Vulnerability != vuln {
		t.Errorf("expected the record to be reported, got %v", flattened[0].Vulnerability)
	}
	if diff := cmp.Diff(models.GroupInfo{}, flattened[0].GroupInfo); diff != "" {
		t.Errorf("expected an ungrouped record to have no group info (-want +got):\n%s", diff)
	}
}
