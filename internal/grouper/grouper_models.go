package grouper

import (
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type IDAliases struct {
	ID      string
	Aliases []string
}

// ConvertVulnerabilityToIDAliases converts vulnerability records into the
// records that Group works with.
//
// The returned records are in the same order as the given vulnerabilities;
// Group does not depend on that order, and this function does not modify the
// given vulnerabilities or reuse their slices, so the original records (and
// the sources that reported them) remain untouched and traceable.
func ConvertVulnerabilityToIDAliases(c []*osvschema.Vulnerability) []IDAliases {
	output := make([]IDAliases, 0, len(c))

	for _, v := range c {
		// Clone the aliases so we never append into the vulnerability's own
		// backing array and modify the original record.
		aliases := slices.Clone(v.GetAliases())

		// For Ubuntu Security Advisory data,
		// all related CVEs should be bundled together, as they are part of this USN.
		// TODO(jesslowe): remove after all USNs are migrated.
		if strings.Split(v.GetId(), "-")[0] == "USN" {
			aliases = append(aliases, v.GetRelated()...)
		}

		output = append(output, IDAliases{
			ID:      v.GetId(),
			Aliases: aliases,
		})
	}

	return output
}
