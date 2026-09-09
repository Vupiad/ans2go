package ast

// Node is the base interface for all AST nodes.
type Node interface {
	node()
}

// Type represents an ASN.1 type.
type Type interface {
	Node
	typeName() string
}

// File represents a parsed ASN.1 file containing one or more modules.
type File struct {
	Path    string
	Modules []*Module
}

func (f *File) node() {}

// Module represents an ASN.1 module (e.g. `SUPL-INIT DEFINITIONS AUTOMATIC TAGS ::= BEGIN ... END`).
type Module struct {
	Name             string
	TagDefault       string
	Exports          []string
	Imports          []*Import
	TypeAssignments  []*TypeAssignment
	ValueAssignments []*ValueAssignment
}

func (m *Module) node() {}

// Import represents symbols imported from another module.
type Import struct {
	Symbols    []string
	FromModule string
}

func (i *Import) node() {}

// ValueAssignment represents a value definition like `maxReqLength INTEGER ::= 50`.
type ValueAssignment struct {
	Name  string
	Type  Type
	Value int64
}

func (v *ValueAssignment) node() {}

// TypeAssignment represents a type definition like `Version ::= SEQUENCE { ... }`.
type TypeAssignment struct {
	Name string
	Type Type
}

func (t *TypeAssignment) node() {}

// IntegerType represents an ASN.1 INTEGER with optional constraints.
type IntegerType struct {
	MinStr        string
	MaxStr        string
	MinVal        int64
	MaxVal        int64
	IsConstrained bool
}

func (t *IntegerType) node()            {}
func (t *IntegerType) typeName() string { return "INTEGER" }

// BooleanType represents an ASN.1 BOOLEAN.
type BooleanType struct{}

func (t *BooleanType) node()            {}
func (t *BooleanType) typeName() string { return "BOOLEAN" }

// NamedBit represents a named bit in BIT STRING { bitName (0), ... }.
type NamedBit struct {
	Name string
	Bit  int
}

// BitStringType represents an ASN.1 BIT STRING with optional size constraint and named bits.
type BitStringType struct {
	MinSizeStr string
	MaxSizeStr string
	MinSize    int
	MaxSize    int
	HasSize    bool
	NamedBits  []NamedBit
}

func (t *BitStringType) node()            {}
func (t *BitStringType) typeName() string { return "BIT STRING" }

// OctetStringType represents an ASN.1 OCTET STRING with optional size constraint.
type OctetStringType struct {
	MinSizeStr string
	MaxSizeStr string
	MinSize    int
	MaxSize    int
	HasSize    bool
}

func (t *OctetStringType) node()            {}
func (t *OctetStringType) typeName() string { return "OCTET STRING" }

// CharacterStringType represents IA5String or VisibleString with optional size & alphabet constraints.
type CharacterStringType struct {
	Kind       string // "IA5String", "VisibleString"
	MinSizeStr string
	MaxSizeStr string
	MinSize    int
	MaxSize    int
	HasSize    bool
	Alphabet   []string // e.g. ["a-z", "A-Z", "0-9", ".-"]
}

func (t *CharacterStringType) node()            {}
func (t *CharacterStringType) typeName() string { return t.Kind }

// UTCTimeType represents ASN.1 UTCTime.
type UTCTimeType struct{}

func (t *UTCTimeType) node()            {}
func (t *UTCTimeType) typeName() string { return "UTCTime" }

// NullType represents ASN.1 NULL.
type NullType struct{}

func (t *NullType) node()            {}
func (t *NullType) typeName() string { return "NULL" }

// Field represents a field in a SEQUENCE.
type Field struct {
	Name     string
	Type     Type
	Optional bool
}

// SequenceType represents an ASN.1 SEQUENCE.
type SequenceType struct {
	Fields          []*Field
	Extensible      bool
	ExtensionFields []*Field
}

func (t *SequenceType) node()            {}
func (t *SequenceType) typeName() string { return "SEQUENCE" }

// Alternative represents an alternative in a CHOICE.
type Alternative struct {
	Name string
	Type Type
}

// ChoiceType represents an ASN.1 CHOICE.
type ChoiceType struct {
	Alternatives          []*Alternative
	Extensible            bool
	ExtensionAlternatives []*Alternative
}

func (t *ChoiceType) node()            {}
func (t *ChoiceType) typeName() string { return "CHOICE" }

// SequenceOfType represents an ASN.1 SEQUENCE OF.
type SequenceOfType struct {
	ElementType Type
	MinSizeStr  string
	MaxSizeStr  string
	MinSize     int
	MaxSize     int
	HasSize     bool
}

func (t *SequenceOfType) node()            {}
func (t *SequenceOfType) typeName() string { return "SEQUENCE OF" }

// EnumItem represents an item in an ENUMERATED type.
type EnumItem struct {
	Name     string
	Value    int
	HasValue bool
}

// EnumeratedType represents an ASN.1 ENUMERATED type.
type EnumeratedType struct {
	Items          []*EnumItem
	Extensible     bool
	ExtensionItems []*EnumItem
}

func (t *EnumeratedType) node()            {}
func (t *EnumeratedType) typeName() string { return "ENUMERATED" }

// ReferenceType represents a reference to another ASN.1 type by name.
type ReferenceType struct {
	Name string
}

func (t *ReferenceType) node()            {}
func (t *ReferenceType) typeName() string { return t.Name }
