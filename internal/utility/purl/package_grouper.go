package purl

import (
	"cmp"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/internal/grouper"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Group takes a list of packages, and group them in a map using their PURL
// as key It is a way to have only one instance of each package, even if some has
// been detected multiple times. If the function fails to create a PURL from a
// package, it generates an error, continue to group the other packages and
// reports both grouped packages and all generated errors.
//
// When the same package is reported by several sources, the vulnerabilities of
// every occurrence are kept (a security event is only counted once by its ID),
// so a source that reports an extra record for an already seen package does not
// have that record dropped. The groups are rebuilt from the merged records so
// that they describe the merged package, with any analysis already performed
// carried over.
func Group(packageSources []models.PackageSource) (map[string]models.PackageVulns, []error) {
	uniquePackages := make(map[string]models.PackageVulns)
	errors := make([]error, 0)

	for _, packageSource := range packageSources {
		for _, pkg := range packageSource.Packages {
			packageURL, err := FromPackage(pkg.Package)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			key := packageURL.ToString()
			existing, packageExists := uniquePackages[key]
			if !packageExists {
				existing = models.PackageVulns{
					Package: models.PackageInfo{
						Name:       pkg.Package.Name,
						Version:    pkg.Package.Version,
						Ecosystem:  pkg.Package.Ecosystem,
						Deprecated: pkg.Package.Deprecated,
					},
					DepGroups:         slices.Clone(pkg.DepGroups),
					Vulnerabilities:   slices.Clone(pkg.Vulnerabilities),
					Groups:            slices.Clone(pkg.Groups),
					Licenses:          slices.Clone(pkg.Licenses),
					LicenseViolations: slices.Clone(pkg.LicenseViolations),
				}

				uniquePackages[key] = existing

				continue
			}

			// A package reported by several sources: keep every distinct
			// record, dependency group, license and violation. The order the
			// sources are visited in must not affect the merged result.
			merged := existing
			merged.Package.Deprecated = merged.Package.Deprecated || pkg.Package.Deprecated
			merged.DepGroups = mergeStrings(existing.DepGroups, pkg.DepGroups)
			merged.Vulnerabilities = mergeVulnerabilities(existing.Vulnerabilities, pkg.Vulnerabilities)

			if len(merged.Vulnerabilities) == 0 {
				// Nothing to group, and nothing to carry analysis for.
				merged.Groups = nil

				uniquePackages[key] = merged

				continue
			}

			// Rebuild the groups over the merged records, carrying over any
			// analysis that was performed against either occurrence.
			groups := grouper.Build(models.PackageVulns{
				Package:         merged.Package,
				Vulnerabilities: merged.Vulnerabilities,
			}, false)
			grouper.CopyAnalysis(existing.Groups, groups)
			grouper.CopyAnalysis(pkg.Groups, groups)
			merged.Groups = groups

			uniquePackages[key] = merged
		}
	}

	return uniquePackages, errors
}

// mergeStrings returns the union of two string slices in a deterministic order.
func mergeStrings(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}

	merged := slices.Concat(slices.Clone(a), b)
	slices.Sort(merged)

	return slices.Compact(merged)
}

// mergeVulnerabilities returns the records of both slices, deduplicated by ID.
//
// When the same ID is reported more than once, the most complete record is
// kept, with ties broken by the record's deterministic encoding, so that the
// surviving record does not depend on the order the sources were visited in.
func mergeVulnerabilities(a, b []*osvschema.Vulnerability) []*osvschema.Vulnerability {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}

	byID := make(map[string]*osvschema.Vulnerability, len(a)+len(b))
	order := make([]string, 0, len(a)+len(b))

	for _, vuln := range slices.Concat(a, b) {
		existing, ok := byID[vuln.GetId()]
		if !ok {
			byID[vuln.GetId()] = vuln
			order = append(order, vuln.GetId())

			continue
		}

		if compareRecordCompleteness(vuln, existing) < 0 {
			byID[vuln.GetId()] = vuln
		}
	}

	merged := make([]*osvschema.Vulnerability, 0, len(order))
	for _, id := range order {
		merged = append(merged, byID[id])
	}

	return merged
}

// compareRecordCompleteness orders records so that the most informative one
// comes first: a record with a summary and details beats one without, and
// remaining ties are broken by the record's stable fields.
//
// Only exported fields are compared, and no record is serialized or otherwise
// mutated, so comparing records never changes them.
func compareRecordCompleteness(a, b *osvschema.Vulnerability) int {
	return cmp.Or(
		cmp.Compare(completenessScore(b), completenessScore(a)),
		strings.Compare(a.GetSummary(), b.GetSummary()),
		strings.Compare(a.GetDetails(), b.GetDetails()),
		strings.Compare(a.GetModified().String(), b.GetModified().String()),
		cmp.Compare(len(a.GetAffected()), len(b.GetAffected())),
		cmp.Compare(len(a.GetAliases()), len(b.GetAliases())),
	)
}

// completenessScore returns a rough measure of how much information a record
// has, so records describing the same ID can be compared.
func completenessScore(v *osvschema.Vulnerability) int {
	score := 0
	if v.GetSummary() != "" {
		score += 2
	}
	if v.GetDetails() != "" {
		score++
	}
	if severity.CalculateMaxScore(v.GetSeverity()) >= 0 {
		score++
	}
	if len(v.GetAffected()) > 0 {
		score++
	}

	return score
}
