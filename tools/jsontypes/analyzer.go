package jsontypes

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// AnalyzerConfig configures an Analyzer.
type AnalyzerConfig struct {
	// Resolver handles interactive decisions during analysis.
	// If nil, heuristic defaults are used (fully autonomous).
	//
	// When set, the resolver is called only when the analyzer is
	// genuinely unsure: ambiguous map/struct, multiple object shapes,
	// tuple candidates, and unresolvable name collisions. Confident
	// heuristic decisions are made without calling the resolver.
	Resolver Resolver

	// AskTypes prompts for every type name, even when heuristics
	// are confident. Only meaningful when Resolver is set.
	AskTypes bool
}

// Analyzer holds state for a single JSON analysis pass. Create a new
// Analyzer for each JSON document; do not reuse across documents.
type Analyzer struct {
	resolver   Resolver
	autonomous bool
	askTypes   bool

	typeCounter int
	knownTypes  map[string]*structType
	typesByName map[string]*structType
	// pendingTypeName is set by decideMapOrStruct and consumed by
	// decideTypeName to avoid double-prompting.
	pendingTypeName string
}

type structType struct {
	name   string
	fields map[string]string // field name → value kind ("string", "number", "bool", "null", "object", "array", "mixed")
}

type shapeGroup struct {
	fields  []string
	members []map[string]any
}

// New creates an Analyzer with the given configuration.
func New(cfg AnalyzerConfig) *Analyzer {
	r := cfg.Resolver
	autonomous := r == nil
	if r == nil {
		r = defaultResolver
	}
	return &Analyzer{
		resolver:    r,
		autonomous:  autonomous,
		askTypes:    cfg.AskTypes,
		knownTypes:  make(map[string]*structType),
		typesByName: make(map[string]*structType),
	}
}

// Analyze traverses a JSON value depth-first and returns annotated flat paths.
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
	keyName := inferKeyName(obj)

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
	if isTupleCandidate(arr) {
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

	// Multiple shapes — in autonomous mode default to same type
	if a.autonomous {
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

// promptTypeUnification presents shape groups and asks if they are the same
// type (with optional fields) or different types.
func (a *Analyzer) promptTypeUnification(path string, groups map[string]*shapeGroup, groupOrder []string) []string {
	// Compute shared and unique fields across all shapes
	shared, uniquePerShape := shapeFieldBreakdown(groups, groupOrder)

	// Build shape summaries for the resolver
	shapes := make([]ShapeSummary, len(groupOrder))
	for i, sig := range groupOrder {
		g := groups[sig]
		shapes[i] = ShapeSummary{
			Index:        i,
			Instances:    len(g.members),
			Fields:       g.fields,
			UniqueFields: uniquePerShape[sig],
		}
	}

	// Decide default: if unique fields heavily outnumber meaningful shared
	// fields, default to "different".
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
	defaultIsNewType := totalUnique >= 2*meaningfulShared

	d := &Decision{
		Kind:         DecideUnifyShapes,
		Path:         shortPath(path),
		Default:      Response{IsNewType: defaultIsNewType},
		Shapes:       shapes,
		SharedFields: shared,
	}

	// Pre-collect all instances for the common "same type" path.
	var all []map[string]any
	for _, sig := range groupOrder {
		all = append(all, groups[sig].members...)
	}

	if err := a.resolver(d); err != nil {
		return a.analyzeAsStructMulti(path, all)
	}

	if !d.Response.IsNewType {
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
		merged := mergeObjects(g.members)
		newFields := fieldSet(merged)
		shapeSig := shapeSignature(merged)
		inferred = a.preResolveCollision(path, inferred, newFields)

		sd := &Decision{
			Kind:       DecideShapeName,
			Path:       shortPath(path),
			Default:    Response{Name: inferred},
			Fields:     objectToFieldSummaries(merged),
			ShapeIndex: i,
		}
		if err := a.resolver(sd); err != nil {
			names[i] = inferred
		} else {
			names[i] = sd.Response.Name
			if names[i] == "" {
				names[i] = inferred
			}
		}

		// Register early so subsequent shapes see this name as taken
		a.registerType(shapeSig, names[i], newFields)
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
func isTupleCandidate(arr []any) bool {
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
