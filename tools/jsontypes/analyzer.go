package jsontypes

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Analyzer struct {
	Prompter    *Prompter
	anonymous   bool
	askTypes    bool
	typeCounter int
	// knownTypes maps shape signature → type name
	knownTypes map[string]*structType
	// typesByName maps type name → structType for collision detection
	typesByName map[string]*structType
	// pendingTypeName is set by the combined map/struct+name prompt
	// and consumed by decideTypeName to avoid double-prompting
	pendingTypeName string
}

type structType struct {
	name   string
	fields map[string]string // field name → value kind ("string", "number", "bool", "null", "object", "array", "mixed")
}

type shapeGroup struct {
	sig     string
	fields  []string
	members []map[string]any
}

func NewAnalyzer(inputIsStdin, anonymous, askTypes bool) (*Analyzer, error) {
	p, err := NewPrompter(inputIsStdin, anonymous)
	if err != nil {
		return nil, err
	}
	return &Analyzer{
		Prompter:    p,
		anonymous:   anonymous,
		askTypes:    askTypes,
		knownTypes:  make(map[string]*structType),
		typesByName: make(map[string]*structType),
	}, nil
}

func (a *Analyzer) Close() {
	a.Prompter.Close()
}

// analyze traverses a JSON value depth-first and returns annotated flat paths.
func (a *Analyzer) Analyze(path string, val any) []string {
	switch v := val.(type) {
	case nil:
		return []string{path + "{null}"}
	case bool:
		return []string{path + "{bool}"}
	case json.Number:
		if _, err := v.Int64(); err == nil {
			return []string{path + "{int}"}
		}
		return []string{path + "{float}"}
	case string:
		return []string{path + "{string}"}
	case []any:
		return a.analyzeArray(path, v)
	case map[string]any:
		return a.analyzeObject(path, v)
	default:
		return []string{path + "{unknown}"}
	}
}

func (a *Analyzer) analyzeObject(path string, obj map[string]any) []string {
	if len(obj) == 0 {
		return []string{path + "{any}"}
	}

	isMap := a.decideMapOrStruct(path, obj)
	if isMap {
		return a.analyzeAsMap(path, obj)
	}
	return a.analyzeAsStruct(path, obj)
}

func (a *Analyzer) analyzeAsMap(path string, obj map[string]any) []string {
	keyName := a.decideKeyName(path, obj)

	// Collect all values and group by shape for type unification
	values := make([]any, 0, len(obj))
	for _, v := range obj {
		values = append(values, v)
	}

	return a.analyzeCollectionValues(path+"["+keyName+"]", values)
}

func (a *Analyzer) analyzeAsStruct(path string, obj map[string]any) []string {
	return a.analyzeAsStructMulti(path, []map[string]any{obj})
}

// analyzeAsStructMulti handles one or more instances of the same struct type,
// collecting all values for each field across instances for proper unification.
func (a *Analyzer) analyzeAsStructMulti(path string, instances []map[string]any) []string {
	// Collect all field names across all instances
	merged := mergeObjects(instances)
	typeName := a.decideTypeName(path, merged)

	prefix := path + "{" + typeName + "}"
	var paths []string
	keys := sortedKeys(merged)
	for _, k := range keys {
		// Collect all values for this field across instances
		var fieldValues []any
		fieldPresent := 0
		for _, inst := range instances {
			if v, ok := inst[k]; ok {
				fieldValues = append(fieldValues, v)
				fieldPresent++
			}
		}
		// If the field is missing in some instances, it's optional
		if fieldPresent < len(instances) {
			paths = append(paths, prefix+"."+k+"{null}")
		}

		if len(fieldValues) == 1 {
			childPaths := a.Analyze(prefix+"."+k, fieldValues[0])
			paths = append(paths, childPaths...)
		} else if len(fieldValues) > 1 {
			childPaths := a.analyzeCollectionValues(prefix+"."+k, fieldValues)
			paths = append(paths, childPaths...)
		}
	}
	if len(paths) == 0 {
		paths = append(paths, prefix)
	}
	return paths
}

func (a *Analyzer) analyzeArray(path string, arr []any) []string {
	if len(arr) == 0 {
		return []string{path + "[]{any}"}
	}

	// Check for tuple (short array of mixed types)
	if a.isTupleCandidate(arr) {
		isTuple := a.decideTupleOrList(path, arr)
		if isTuple {
			return a.analyzeAsTuple(path, arr)
		}
	}

	return a.analyzeCollectionValues(path+"[]", arr)
}

func (a *Analyzer) analyzeAsTuple(path string, arr []any) []string {
	var paths []string
	for i, v := range arr {
		childPaths := a.Analyze(fmt.Sprintf("%s[%d]", path, i), v)
		paths = append(paths, childPaths...)
	}
	return paths
}

// analyzeCollectionValues handles type unification for a set of values at the
// same path position (map values or array elements).
func (a *Analyzer) analyzeCollectionValues(path string, values []any) []string {
	// Group values by kind
	var (
		nullCount   int
		objects     []map[string]any
		arrays      [][]any
		primitives  []any
		primTypeSet = make(map[string]bool)
	)

	for _, v := range values {
		switch tv := v.(type) {
		case nil:
			nullCount++
		case map[string]any:
			objects = append(objects, tv)
		case []any:
			arrays = append(arrays, tv)
		default:
			primitives = append(primitives, v)
			primTypeSet[primitiveType(v)] = true
		}
	}

	var paths []string

	// Handle nulls: indicates the value is optional
	if nullCount > 0 && (len(objects) > 0 || len(arrays) > 0 || len(primitives) > 0) {
		paths = append(paths, path+"{null}")
	} else if nullCount > 0 && len(objects) == 0 && len(arrays) == 0 && len(primitives) == 0 {
		return []string{path + "{null}"}
	}

	// Handle primitives
	for pt := range primTypeSet {
		paths = append(paths, path+"{"+pt+"}")
	}

	// Handle objects by grouping by shape and unifying
	if len(objects) > 0 {
		paths = append(paths, a.unifyObjects(path, objects)...)
	}

	// Handle arrays: collect all elements across all array instances
	if len(arrays) > 0 {
		var allElements []any
		for _, arr := range arrays {
			allElements = append(allElements, arr...)
		}
		if len(allElements) > 0 {
			paths = append(paths, a.analyzeCollectionValues(path+"[]", allElements)...)
		} else {
			paths = append(paths, path+"[]{any}")
		}
	}

	return paths
}

// unifyObjects groups objects by shape, prompts about type relationships,
// and returns the unified paths.
func (a *Analyzer) unifyObjects(path string, objects []map[string]any) []string {
	// Before grouping by shape, check if these objects are really maps by
	// pooling all keys across all instances. Individual objects may have too
	// few keys for heuristics, but collectively the pattern is clear.
	if combined := a.tryAnalyzeAsMaps(path, objects); combined != nil {
		return combined
	}

	groups := make(map[string]*shapeGroup)
	var groupOrder []string

	for _, obj := range objects {
		sig := shapeSignature(obj)
		if g, ok := groups[sig]; ok {
			g.members = append(g.members, obj)
		} else {
			g := &shapeGroup{
				sig:     sig,
				fields:  sortedKeys(obj),
				members: []map[string]any{obj},
			}
			groups[sig] = g
			groupOrder = append(groupOrder, sig)
		}
	}

	if len(groups) == 1 {
		// All same shape, analyze with all instances for field unification
		return a.analyzeAsStructMulti(path, objects)
	}

	// Multiple shapes — in anonymous mode default to same type
	if a.anonymous {
		return a.analyzeAsStructMulti(path, objects)
	}
	return a.promptTypeUnification(path, groups, groupOrder)
}

// tryAnalyzeAsMaps pools all keys from multiple objects and checks if they
// collectively look like map keys (e.g., many objects each with 1-2 numeric
// keys). Returns nil if they don't look like maps.
func (a *Analyzer) tryAnalyzeAsMaps(path string, objects []map[string]any) []string {
	// Collect all keys across all objects
	allKeys := make(map[string]bool)
	for _, obj := range objects {
		for k := range obj {
			allKeys[k] = true
		}
	}

	// Need enough keys to be meaningful
	if len(allKeys) < 3 {
		return nil
	}

	// Build a synthetic object with all keys for heuristic checking
	combined := make(map[string]any, len(allKeys))
	for _, obj := range objects {
		for k, v := range obj {
			if _, exists := combined[k]; !exists {
				combined[k] = v
			}
		}
	}

	isMap, confident := looksLikeMap(combined)
	if !isMap || !confident {
		return nil
	}

	// These are maps — merge all entries and analyze as one map
	return a.analyzeAsMap(path, combined)
}

// promptTypeUnification presents shape groups to the user and asks if they
// are the same type (with optional fields) or different types.
func (a *Analyzer) promptTypeUnification(path string, groups map[string]*shapeGroup, groupOrder []string) []string {
	const maxFields = 8

	// Compute shared and unique fields across all shapes
	shared, uniquePerShape := shapeFieldBreakdown(groups, groupOrder)
	totalInstances := 0
	for _, sig := range groupOrder {
		totalInstances += len(groups[sig].members)
	}

	fmt.Fprintf(a.Prompter.output, "\nAt %s — %d shapes (%d instances):\n",
		shortPath(path), len(groupOrder), totalInstances)

	// Show shared fields
	if len(shared) > 0 {
		preview := shared
		if len(preview) > maxFields {
			preview = preview[:maxFields]
		}
		fmt.Fprintf(a.Prompter.output, "  shared fields (%d): %s", len(shared), strings.Join(preview, ", "))
		if len(shared) > maxFields {
			fmt.Fprintf(a.Prompter.output, ", ...")
		}
		fmt.Fprintln(a.Prompter.output)
	} else {
		fmt.Fprintf(a.Prompter.output, "  no shared fields\n")
	}

	// Show unique fields per shape (truncated)
	shownShapes := groupOrder
	if len(shownShapes) > 5 {
		shownShapes = shownShapes[:5]
	}
	for i, sig := range shownShapes {
		g := groups[sig]
		unique := uniquePerShape[sig]
		if len(unique) == 0 {
			fmt.Fprintf(a.Prompter.output, "  shape %d (%d instances): no unique fields\n", i+1, len(g.members))
			continue
		}
		preview := unique
		if len(preview) > maxFields {
			preview = preview[:maxFields]
		}
		fmt.Fprintf(a.Prompter.output, "  shape %d (%d instances): +%d unique: %s",
			i+1, len(g.members), len(unique), strings.Join(preview, ", "))
		if len(unique) > maxFields {
			fmt.Fprintf(a.Prompter.output, ", ...")
		}
		fmt.Fprintln(a.Prompter.output)
	}
	if len(groupOrder) > 5 {
		fmt.Fprintf(a.Prompter.output, "  ... and %d more shapes\n", len(groupOrder)-5)
	}

	// Decide default: if unique fields heavily outnumber meaningful shared
	// fields, default to "different". Ubiquitous fields (id, name, *_at, etc.)
	// don't count as meaningful shared fields.
	meaningfulShared := 0
	for _, f := range shared {
		if !isUbiquitousField(f) {
			meaningfulShared++
		}
	}
	totalUnique := 0
	for _, sig := range groupOrder {
		totalUnique += len(uniquePerShape[sig])
	}
	defaultChoice := "s"
	if totalUnique >= 2*meaningfulShared {
		defaultChoice = "d"
	}

	// Combined prompt: same/different/show full list
	var choice string
	for {
		choice = a.Prompter.ask(
			"[s]ame type? [d]ifferent? show [f]ull list?",
			defaultChoice, []string{"s", "d", "f"},
		)
		if choice != "f" {
			break
		}
		for i, sig := range groupOrder {
			g := groups[sig]
			fmt.Fprintf(a.Prompter.output, "  Shape %d (%d instances): %s\n",
				i+1, len(g.members), strings.Join(g.fields, ", "))
		}
	}

	if choice == "s" {
		// Same type — analyze with all instances for field unification
		var all []map[string]any
		for _, sig := range groupOrder {
			all = append(all, groups[sig].members...)
		}
		return a.analyzeAsStructMulti(path, all)
	}

	// Different types — collect all names first, then analyze
	names := make([]string, len(groupOrder))
	for i, sig := range groupOrder {
		g := groups[sig]
		inferred := inferTypeName(path)
		if inferred == "" {
			a.typeCounter++
			inferred = fmt.Sprintf("Struct%d", a.typeCounter)
		}
		// Pre-resolve collision so the suggested name is valid
		merged := mergeObjects(g.members)
		newFields := fieldSet(merged)
		shapeSig := shapeSignature(merged)
		inferred = a.preResolveCollision(path, inferred, newFields, shapeSig)

		fmt.Fprintf(a.Prompter.output, "  Shape %d (%d instances): %s\n",
			i+1, len(g.members), strings.Join(g.fields, ", "))
		name := a.Prompter.askTypeName(
			fmt.Sprintf("  Name for shape %d?", i+1), inferred)
		names[i] = name

		// Register early so subsequent shapes see this name as taken
		a.registerType(shapeSig, name, newFields)
	}

	// Now analyze each group with its pre-assigned name
	var paths []string
	for i, sig := range groupOrder {
		g := groups[sig]
		a.pendingTypeName = names[i]
		paths = append(paths, a.analyzeAsStructMulti(path, g.members)...)
	}
	return paths
}

// shapeFieldBreakdown computes the shared fields (present in ALL shapes) and
// unique fields (present in only that shape) for display.
func shapeFieldBreakdown(groups map[string]*shapeGroup, groupOrder []string) (shared []string, uniquePerShape map[string][]string) {
	if len(groupOrder) == 0 {
		return nil, nil
	}

	// Count how many shapes each field appears in
	fieldCount := make(map[string]int)
	for _, sig := range groupOrder {
		for _, f := range groups[sig].fields {
			fieldCount[f]++
		}
	}

	total := len(groupOrder)
	for _, f := range sortedFieldCount(fieldCount) {
		if fieldCount[f] == total {
			shared = append(shared, f)
		}
	}

	sharedSet := make(map[string]bool, len(shared))
	for _, f := range shared {
		sharedSet[f] = true
	}

	uniquePerShape = make(map[string][]string)
	for _, sig := range groupOrder {
		var unique []string
		for _, f := range groups[sig].fields {
			if !sharedSet[f] {
				unique = append(unique, f)
			}
		}
		uniquePerShape[sig] = unique
	}
	return shared, uniquePerShape
}

func sortedFieldCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// isTupleCandidate returns true if the array might be a tuple:
// short (2-5 elements) with mixed types.
func (a *Analyzer) isTupleCandidate(arr []any) bool {
	if len(arr) < 2 || len(arr) > 5 {
		return false
	}
	types := make(map[string]bool)
	for _, v := range arr {
		types[kindOf(v)] = true
	}
	return len(types) > 1
}

func primitiveType(v any) string {
	switch tv := v.(type) {
	case bool:
		return "bool"
	case json.Number:
		if _, err := tv.Int64(); err == nil {
			return "int"
		}
		return "float"
	case string:
		return "string"
	default:
		return "unknown"
	}
}

func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

func shapeSignature(obj map[string]any) string {
	keys := sortedKeys(obj)
	return strings.Join(keys, ",")
}

func sortedKeys(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// mergeObjects merges multiple objects into one representative that has all
// fields from all instances. For each field, picks the first non-null value.
func mergeObjects(objects []map[string]any) map[string]any {
	merged := make(map[string]any)
	for _, obj := range objects {
		for k, v := range obj {
			if existing, ok := merged[k]; !ok || existing == nil {
				merged[k] = v
			}
		}
	}
	return merged
}
