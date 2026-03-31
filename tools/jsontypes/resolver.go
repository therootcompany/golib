package jsontypes

// DecisionKind identifies the type of decision being requested.
type DecisionKind int

const (
	// DecideMapOrStruct asks whether a JSON object is a map (dynamic keys)
	// or a struct (fixed fields).
	// Relevant Decision fields: Fields.
	// Response: set IsMap=true, or set Name to a PascalCase type name.
	DecideMapOrStruct DecisionKind = iota

	// DecideTypeName asks what a struct type should be called.
	// Relevant Decision fields: Fields.
	// Response: set Name to a PascalCase type name.
	DecideTypeName

	// DecideTupleOrList asks whether a short mixed-type array is a tuple
	// (fixed positional types) or a homogeneous list.
	// Relevant Decision fields: Elements.
	// Response: set IsTuple.
	DecideTupleOrList

	// DecideUnifyShapes asks whether multiple object shapes at the same
	// JSON position represent the same type (with optional fields) or
	// different types.
	// Relevant Decision fields: Shapes, SharedFields.
	// Response: set IsNewType to treat each shape as a separate type.
	DecideUnifyShapes

	// DecideShapeName asks what a specific shape variant should be called
	// when the user chose "different types" for a UnifyShapes decision.
	// Relevant Decision fields: ShapeIndex, Fields.
	// Response: set Name to a PascalCase type name.
	DecideShapeName

	// DecideNameCollision asks what to do when a chosen type name is
	// already registered with overlapping but incompatible fields.
	// Relevant Decision fields: Fields (new), ExistingFields.
	// Response: set Extend=true to merge fields, or set Name to a
	// different PascalCase type name.
	DecideNameCollision
)

// Decision represents a question posed during JSON analysis.
// The Kind field determines which context fields are populated.
type Decision struct {
	Kind    DecisionKind
	Path    string   // JSON path being analyzed
	Default Response // heuristic suggestion

	// Fields describes the object's keys and value types.
	// Populated for MapOrStruct, TypeName, ShapeName, NameCollision.
	Fields []FieldSummary

	// Elements describes array element values.
	// Populated for TupleOrList.
	Elements []ElementSummary

	// Shapes describes multiple object shapes at the same position.
	// Populated for UnifyShapes.
	Shapes []ShapeSummary

	// SharedFields lists field names common to all shapes.
	// Populated for UnifyShapes.
	SharedFields []string

	// ShapeIndex identifies which shape is being named (0-based).
	// Populated for ShapeName.
	ShapeIndex int

	// ExistingFields lists the fields of the already-registered type
	// whose name collides with the requested name.
	// Populated for NameCollision.
	ExistingFields []string

	// Response is set by the Resolver to communicate the decision.
	Response Response
}

// Response carries the answer to a Decision.
// Which fields are meaningful depends on the Decision.Kind.
type Response struct {
	// Name is a PascalCase type name.
	// Used by MapOrStruct (when not a map), TypeName, ShapeName,
	// and NameCollision (when not extending).
	Name string

	// IsMap indicates the object should be treated as a map.
	// Used by MapOrStruct.
	IsMap bool

	// IsTuple indicates the array is a tuple.
	// Used by TupleOrList.
	IsTuple bool

	// IsNewType indicates each shape should be a separate type rather than
	// unifying into one type with optional fields.
	// Used by UnifyShapes. Zero value (false) means unify into one type.
	IsNewType bool

	// Extend indicates the existing type should be extended with merged
	// fields rather than choosing a new name.
	// Used by NameCollision.
	Extend bool
}

// FieldSummary describes a single field in a JSON object.
type FieldSummary struct {
	Name    string // JSON field name
	Kind    string // "string", "number", "bool", "null", "object", "array"
	Preview string // human-readable value summary
}

// ElementSummary describes a single element in a JSON array.
type ElementSummary struct {
	Index   int
	Kind    string
	Preview string
}

// ShapeSummary describes one shape group in a multi-shape decision.
type ShapeSummary struct {
	Index        int      // 0-based shape index
	Instances    int      // how many objects have this shape
	Fields       []string // all field names in this shape
	UniqueFields []string // fields unique to this shape (not in other shapes)
}

// Resolver is called during analysis when a decision is needed.
// The resolver reads the Decision's context fields and sets
// Decision.Response before returning. If an error is returned,
// heuristic defaults are used for that decision.
//
// To accept the heuristic default: d.Response = d.Default.
type Resolver func(d *Decision) error

// defaultResolver accepts heuristic defaults for all decisions.
func defaultResolver(d *Decision) error {
	d.Response = d.Default
	return nil
}
