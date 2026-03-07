package jsontypes

import (
	"sort"
	"strings"
)

// segment represents one part of a parsed path.
type segment struct {
	name  string // field name (empty for root)
	index string // "[]", "[int]", "[string]", etc. (can be multiple like "[int][]")
	typ   string // type name without braces, e.g. "Room", "string", "null"
}

// parsePath splits a full annotated path into segments.
// e.g., ".{RoomsResult}.rooms[]{Room}.name{string}" →
//
//	[{name:"", typ:"RoomsResult"}, {name:"rooms", index:"[]", typ:"Room"}, {name:"name", typ:"string"}]
func parsePath(path string) []segment {
	var segments []segment
	i := 0
	for i < len(path) {
		var seg segment
		// Skip dot prefix
		if i < len(path) && path[i] == '.' {
			i++
		}
		// Name: read until [, {, ., or end
		nameStart := i
		for i < len(path) && path[i] != '[' && path[i] != '{' && path[i] != '.' {
			i++
		}
		seg.name = path[nameStart:i]

		// Indices: read all [...] sequences
		for i < len(path) && path[i] == '[' {
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				break
			}
			seg.index += path[i : i+end+1]
			i = i + end + 1
		}

		// Type: read {Type}
		if i < len(path) && path[i] == '{' {
			end := strings.IndexByte(path[i:], '}')
			if end < 0 {
				break
			}
			seg.typ = path[i+1 : i+end]
			i = i + end + 1
		}

		segments = append(segments, seg)
	}
	return segments
}

// formatPaths converts fully-annotated flat paths into the display format where:
//   - The root type appears alone on the first line (no leading dot)
//   - Each type introduction gets its own line
//   - Type annotations only appear on the rightmost (new) segment of each line
//   - When multiple types share a path position, child fields include the
//     parent type to disambiguate (e.g., .items[]{FileField}.slug{string})
func FormatPaths(paths []string) []string {
	// First pass: find bare positions where multiple types are introduced.
	// These need parent type disambiguation in their child lines.
	typeIntros := make(map[string]map[string]bool) // bare → set of type names
	for _, path := range paths {
		segs := parsePath(path)
		for depth := range segs {
			if segs[depth].typ == "" {
				continue
			}
			bare := buildBare(segs[:depth+1])
			if typeIntros[bare] == nil {
				typeIntros[bare] = make(map[string]bool)
			}
			typeIntros[bare][segs[depth].typ] = true
		}
	}
	// Collect bare paths with multiple types (excluding primitives/null)
	multiType := make(map[string]bool)
	for bare, types := range typeIntros {
		named := 0
		for typ := range types {
			if typ != "null" && typ != "string" && typ != "int" &&
				typ != "float" && typ != "bool" && typ != "unknown" {
				named++
			}
		}
		if named > 1 {
			multiType[bare] = true
		}
	}

	seen := make(map[string]bool)
	var lines []outputLine

	for _, path := range paths {
		segs := parsePath(path)

		for depth := range segs {
			if segs[depth].typ == "" {
				continue
			}

			// Check if the parent position has multiple types
			parentIdx := -1
			if depth > 0 {
				parentBare := buildBare(segs[:depth])
				if multiType[parentBare] {
					// Find the parent segment that has a type
					for j := depth - 1; j >= 0; j-- {
						if segs[j].typ != "" {
							parentIdx = j
							break
						}
					}
				}
			}

			// Check if this position itself has multiple types (type intro line)
			selfBare := buildBare(segs[:depth+1])
			selfMulti := multiType[selfBare]

			var display string
			if parentIdx >= 0 {
				display = buildDisplayWithParent(segs[:depth+1], depth, parentIdx)
			} else {
				display = buildDisplay(segs[:depth+1], depth)
			}
			if !seen[display] {
				seen[display] = true
				var bare string
				if parentIdx >= 0 {
					bare = buildBareWithParent(segs[:depth+1], parentIdx)
				} else if selfMulti {
					// This is a type intro at a multi-type position;
					// include own type in bare so children sort under it.
					bare = buildBareWithParent(segs[:depth+1], depth)
				} else {
					bare = buildBare(segs[:depth+1])
				}
				lines = append(lines, outputLine{bare, display})
			}
		}
	}

	// Merge {null} with sibling types: if a bare path has both {null} and
	// {SomeType}, replace with {SomeType?} and drop the {null} line.
	lines = mergeNullables(lines)

	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].bare != lines[j].bare {
			return lines[i].bare < lines[j].bare
		}
		return lines[i].display < lines[j].display
	})

	result := make([]string, len(lines))
	for i, l := range lines {
		result[i] = l.display
	}
	return result
}

// buildDisplay builds a display line where only the segment at typeIdx shows
// its type. Parent segments are bare. The root segment has no leading dot.
func buildDisplay(segs []segment, typeIdx int) string {
	var buf strings.Builder
	for i, seg := range segs {
		if seg.name != "" {
			buf.WriteByte('.')
			buf.WriteString(seg.name)
		}
		buf.WriteString(seg.index)
		if i == typeIdx {
			buf.WriteByte('{')
			buf.WriteString(seg.typ)
			buf.WriteByte('}')
		}
	}
	s := buf.String()
	if s == "" && len(segs) > 0 && segs[0].typ != "" {
		return "{" + segs[0].typ + "}"
	}
	return s
}

type outputLine struct {
	bare    string // path without types, for sorting
	display string
}

// mergeNullables finds bare paths that have both a {null} line and typed
// lines. It adds ? to the typed lines and drops the {null} line.
// e.g., ".score{null}" + ".score{float}" → ".score{float?}"
func mergeNullables(lines []outputLine) []outputLine {
	// Group lines by bare path
	byBare := make(map[string][]int) // bare → indices into lines
	for i, l := range lines {
		byBare[l.bare] = append(byBare[l.bare], i)
	}

	drop := make(map[int]bool)
	for _, indices := range byBare {
		if len(indices) < 2 {
			continue
		}
		// Check if any line in this group is {null}
		nullIdx := -1
		hasNonNull := false
		for _, idx := range indices {
			if strings.HasSuffix(lines[idx].display, "{null}") {
				nullIdx = idx
			} else {
				hasNonNull = true
			}
		}
		if nullIdx < 0 || !hasNonNull {
			continue
		}
		// Drop the {null} line and add ? to the others
		drop[nullIdx] = true
		for _, idx := range indices {
			if idx == nullIdx {
				continue
			}
			d := lines[idx].display
			// Replace trailing } with ?}
			if strings.HasSuffix(d, "}") {
				lines[idx].display = d[:len(d)-1] + "?}"
			}
		}
	}

	if len(drop) == 0 {
		return lines
	}
	result := make([]outputLine, 0, len(lines)-len(drop))
	for i, l := range lines {
		if !drop[i] {
			result = append(result, l)
		}
	}
	return result
}

// buildDisplayWithParent builds a display line showing type annotations at both
// parentIdx (for disambiguation) and typeIdx (for the new type introduction).
func buildDisplayWithParent(segs []segment, typeIdx, parentIdx int) string {
	var buf strings.Builder
	for i, seg := range segs {
		if seg.name != "" {
			buf.WriteByte('.')
			buf.WriteString(seg.name)
		}
		buf.WriteString(seg.index)
		if i == parentIdx || i == typeIdx {
			buf.WriteByte('{')
			buf.WriteString(seg.typ)
			buf.WriteByte('}')
		}
	}
	s := buf.String()
	if s == "" && len(segs) > 0 && segs[0].typ != "" {
		return "{" + segs[0].typ + "}"
	}
	return s
}

// buildBareWithParent builds a bare path that includes the parent type for
// sorting/grouping, so children of different parent types sort separately.
func buildBareWithParent(segs []segment, parentIdx int) string {
	var buf strings.Builder
	for i, seg := range segs {
		if seg.name != "" {
			buf.WriteByte('.')
			buf.WriteString(seg.name)
		}
		buf.WriteString(seg.index)
		if i == parentIdx {
			buf.WriteByte('{')
			buf.WriteString(seg.typ)
			buf.WriteByte('}')
		}
	}
	return buf.String()
}

// buildBare builds a path string without any type annotations, for sorting.
func buildBare(segs []segment) string {
	var buf strings.Builder
	for _, seg := range segs {
		if seg.name != "" {
			buf.WriteByte('.')
			buf.WriteString(seg.name)
		}
		buf.WriteString(seg.index)
	}
	return buf.String()
}
