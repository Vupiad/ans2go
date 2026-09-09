package analyzer

import (
	"fmt"
	"strconv"
	"strings"

	"ans2go/pkg/asn1/ast"
)

// ResolvedModel contains all parsed and resolved types and constants.
type ResolvedModel struct {
	Constants map[string]int64
	Types     map[string]*ast.TypeAssignment
	Order     []string // deterministic order of type names
}

// Analyze processes all modules across all AST files and produces a ResolvedModel.
func Analyze(files []*ast.File) (*ResolvedModel, error) {
	model := &ResolvedModel{
		Constants: make(map[string]int64),
		Types:     make(map[string]*ast.TypeAssignment),
	}

	// 1. Collect all constants
	for _, file := range files {
		for _, mod := range file.Modules {
			for _, val := range mod.ValueAssignments {
				model.Constants[val.Name] = val.Value
			}
		}
	}

	// 2. Collect all types
	for _, file := range files {
		for _, mod := range file.Modules {
			for _, typeDef := range mod.TypeAssignments {
				if _, exists := model.Types[typeDef.Name]; exists {
					// Duplicate check (all 220 symbols are unique in supl1)
					return nil, fmt.Errorf("duplicate type definition %s in module %s", typeDef.Name, mod.Name)
				}
				model.Types[typeDef.Name] = typeDef
				model.Order = append(model.Order, typeDef.Name)
			}
		}
	}

	// 3. Flatten anonymous inline types & resolve constraints
	typeNames := make([]string, len(model.Order))
	copy(typeNames, model.Order)

	for _, name := range typeNames {
		typeDef := model.Types[name]
		newType, err := model.flattenAndResolve(name, typeDef.Type)
		if err != nil {
			return nil, fmt.Errorf("resolving type %s: %w", name, err)
		}
		typeDef.Type = newType
	}

	return model, nil
}

func (m *ResolvedModel) resolveIntBound(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		return val, nil
	}
	if val, ok := m.Constants[s]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("unresolved integer constant or bound: %q", s)
}

func (m *ResolvedModel) flattenAndResolve(parentName string, t ast.Type) (ast.Type, error) {
	switch typ := t.(type) {
	case *ast.IntegerType:
		if typ.IsConstrained {
			minVal, err := m.resolveIntBound(typ.MinStr)
			if err != nil {
				return nil, err
			}
			maxVal, err := m.resolveIntBound(typ.MaxStr)
			if err != nil {
				return nil, err
			}
			typ.MinVal = minVal
			typ.MaxVal = maxVal
		}
		return typ, nil

	case *ast.BitStringType:
		if typ.HasSize {
			minVal, err := m.resolveIntBound(typ.MinSizeStr)
			if err != nil {
				return nil, err
			}
			maxVal, err := m.resolveIntBound(typ.MaxSizeStr)
			if err != nil {
				return nil, err
			}
			typ.MinSize = int(minVal)
			typ.MaxSize = int(maxVal)
		}
		return typ, nil

	case *ast.OctetStringType:
		if typ.HasSize {
			minVal, err := m.resolveIntBound(typ.MinSizeStr)
			if err != nil {
				return nil, err
			}
			maxVal, err := m.resolveIntBound(typ.MaxSizeStr)
			if err != nil {
				return nil, err
			}
			typ.MinSize = int(minVal)
			typ.MaxSize = int(maxVal)
		}
		return typ, nil

	case *ast.CharacterStringType:
		if typ.HasSize {
			minVal, err := m.resolveIntBound(typ.MinSizeStr)
			if err != nil {
				return nil, err
			}
			maxVal, err := m.resolveIntBound(typ.MaxSizeStr)
			if err != nil {
				return nil, err
			}
			typ.MinSize = int(minVal)
			typ.MaxSize = int(maxVal)
		}
		return typ, nil

	case *ast.SequenceOfType:
		if typ.HasSize {
			minVal, err := m.resolveIntBound(typ.MinSizeStr)
			if err != nil {
				return nil, err
			}
			maxVal, err := m.resolveIntBound(typ.MaxSizeStr)
			if err != nil {
				return nil, err
			}
			typ.MinSize = int(minVal)
			typ.MaxSize = int(maxVal)
		}
		elemType, err := m.flattenAndResolve(parentName+"_Element", typ.ElementType)
		if err != nil {
			return nil, err
		}
		typ.ElementType = elemType
		return typ, nil

	case *ast.SequenceType:
		for _, f := range typ.Fields {
			subName := parentName + "_" + f.Name
			resType, err := m.liftIfComposite(subName, f.Type)
			if err != nil {
				return nil, err
			}
			f.Type = resType
		}
		for _, f := range typ.ExtensionFields {
			subName := parentName + "_" + f.Name
			resType, err := m.liftIfComposite(subName, f.Type)
			if err != nil {
				return nil, err
			}
			f.Type = resType
		}
		return typ, nil

	case *ast.ChoiceType:
		for _, alt := range typ.Alternatives {
			subName := parentName + "_" + alt.Name
			resType, err := m.liftIfComposite(subName, alt.Type)
			if err != nil {
				return nil, err
			}
			alt.Type = resType
		}
		for _, alt := range typ.ExtensionAlternatives {
			subName := parentName + "_" + alt.Name
			resType, err := m.liftIfComposite(subName, alt.Type)
			if err != nil {
				return nil, err
			}
			alt.Type = resType
		}
		return typ, nil

	case *ast.EnumeratedType:
		// Assign consecutive values to unnumbered enum items
		currVal := 0
		for _, it := range typ.Items {
			if it.HasValue {
				currVal = it.Value + 1
			} else {
				it.Value = currVal
				it.HasValue = true
				currVal++
			}
		}
		for _, it := range typ.ExtensionItems {
			if it.HasValue {
				currVal = it.Value + 1
			} else {
				it.Value = currVal
				it.HasValue = true
				currVal++
			}
		}
		return typ, nil

	default:
		return t, nil
	}
}

// liftIfComposite checks if a type is an inline anonymous SEQUENCE, CHOICE, ENUMERATED, or SEQUENCE OF,
// and if so, lifts it to a named top-level TypeAssignment in the model.
func (m *ResolvedModel) liftIfComposite(name string, t ast.Type) (ast.Type, error) {
	switch typ := t.(type) {
	case *ast.SequenceType, *ast.ChoiceType, *ast.EnumeratedType, *ast.SequenceOfType:
		resolved, err := m.flattenAndResolve(name, typ)
		if err != nil {
			return nil, err
		}
		m.Types[name] = &ast.TypeAssignment{
			Name: name,
			Type: resolved,
		}
		m.Order = append(m.Order, name)
		return &ast.ReferenceType{Name: name}, nil
	default:
		return m.flattenAndResolve(name, t)
	}
}
