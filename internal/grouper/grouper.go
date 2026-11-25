// Package grouper groups vulnerabilities by aliases, then sorts them.
package grouper

import (
	"slices"

	"github.com/google/osv-scanner/v2/pkg/models"
)

// disjointSet is a disjoint-set forest over record indices, where each element
// is the index of its parent, and a leader is an element that is its own parent
type disjointSet []int

// find returns the leader of the set that n is in
func (d disjointSet) find(n int) int {
	if d[n] == n {
		return n
	}

	// point n straight at its leader, to save time in future lookups
	d[n] = d.find(d[n])

	return d[n]
}

// union merges the sets that a and b are in, by making the larger leader follow
// the smaller one, so that the leader of each set is always its earliest record
func (d disjointSet) union(a, b int) {
	al := d.find(a)
	bl := d.find(b)

	if al == bl {
		return
	}

	d[max(al, bl)] = min(al, bl)
}

// newDisjointSet returns a disjoint-set forest of n elements, each in their own set
func newDisjointSet(n int) disjointSet {
	d := make(disjointSet, n)

	for i := range d {
		d[i] = i
	}

	return d
}

// Group groups vulnerabilities by aliases.
//
// Records belong to the same group when they share an identifier, either their
// own ID or one of their aliases, so each group is the set of records that
// describe one security event. A source may report that event more than once,
// possibly under different IDs linked by aliases, and the same record may be
// present multiple times.
//
// The result is canonical: the groups, the IDs within each group and each
// group's aliases only depend on the set of records, not on the order that the
// records are given in or which source reported which record. In particular:
//
//   - each record ID appears at most once in a group, so a security event
//     reported by multiple sources keeps a single stable identity;
//   - the IDs of a group are sorted by identifier preference (see
//     identifiers.IDSortFunc), so the first ID is the group's representative;
//   - groups are sorted by their representative ID, so the group order does
//     not depend on the order the records happened to be encountered in.
func Group(vulns []IDAliases) []models.GroupInfo {
	// tracks the first record to have each identifier, so we can tell which
	// earlier record (if any) a later record shares an identifier with
	refs := make(map[string]int)
	groups := newDisjointSet(len(vulns))

	for i, vuln := range vulns {
		for _, id := range slices.Concat([]string{vuln.ID}, vuln.Aliases) {
			// An empty identifier carries no identity, so it must not link
			// otherwise-unrelated records together.
			if id == "" {
				continue
			}

			// if an earlier record has already claimed this identifier, then we're for the
			// same vulnerability so should be in the same group; otherwise we claim it
			if l, ok := refs[id]; ok {
				groups.union(i, l)
			} else {
				refs[id] = i
			}
		}
	}

	// Extract groups into the final result structure, collecting the records
	// that make up each group by the group's leader.
	memberIDs := make(map[int][]string, len(vulns))
	memberAliases := make(map[int][]string, len(vulns))

	for i, vuln := range vulns {
		gid := groups.find(i)

		// Records and aliases without an identifier carry no identity, so
		// they cannot name the security event the group represents.
		if vuln.ID != "" {
			memberIDs[gid] = append(memberIDs[gid], vuln.ID)
		}
		for _, alias := range vuln.Aliases {
			if alias != "" {
				memberAliases[gid] = append(memberAliases[gid], alias)
			}
		}
	}

	result := make([]models.GroupInfo, 0, len(memberIDs))

	for gid, ids := range memberIDs {
		// A group without any ID cannot be identified, so there is no way to
		// report it as a stable security event.
		if len(ids) == 0 {
			continue
		}

		// Add the IDs to the aliases, then put both lists into their canonical
		// form so that a record reported several times does not change the
		// group's identity.
		result = append(result, models.GroupInfo{
			IDs:     ids,
			Aliases: slices.Concat(memberAliases[gid], ids),
		}.Canonicalize())
	}

	// Sort the groups into the canonical order, so that the order of the
	// groups is independent of the order the records were encountered in.
	models.SortGroups(result)

	return result
}
