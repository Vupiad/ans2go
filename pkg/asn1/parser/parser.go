package parser

import (
	"fmt"
	"strconv"

	"ans2go/pkg/asn1/ast"
	"ans2go/pkg/asn1/lexer"
	"ans2go/pkg/asn1/token"
)

// Parser parses ASN.1 token streams into AST nodes.
type Parser struct {
	tokens  []token.Token
	pos     int
	currTok token.Token
}

// New creates a new Parser for the given token slice.
func New(tokens []token.Token) *Parser {
	p := &Parser{
		tokens: tokens,
		pos:    0,
	}
	if len(tokens) > 0 {
		p.currTok = tokens[0]
	} else {
		p.currTok = token.Token{Type: token.EOF}
	}
	return p
}

// ParseFileFromSource parses ASN.1 source text into an ast.File.
func ParseFileFromSource(path string, source string) (*ast.File, error) {
	toks, err := lexer.TokenizeAll(source)
	if err != nil {
		return nil, fmt.Errorf("lexer error in %s: %w", path, err)
	}
	p := New(toks)
	return p.ParseFile(path)
}

func (p *Parser) nextToken() {
	p.pos++
	if p.pos < len(p.tokens) {
		p.currTok = p.tokens[p.pos]
	} else {
		p.currTok = token.Token{Type: token.EOF}
	}
}

func (p *Parser) peekToken() token.Token {
	if p.pos+1 < len(p.tokens) {
		return p.tokens[p.pos+1]
	}
	return token.Token{Type: token.EOF}
}

func (p *Parser) expect(t token.TokenType) error {
	if p.currTok.Type != t {
		return fmt.Errorf("line %d:%d: expected token %v, got %v (%q)", p.currTok.Line, p.currTok.Col, t, p.currTok.Type, p.currTok.Literal)
	}
	p.nextToken()
	return nil
}

// ParseFile parses all modules in a file until EOF.
func (p *Parser) ParseFile(path string) (*ast.File, error) {
	file := &ast.File{
		Path: path,
	}

	for p.currTok.Type != token.EOF {
		mod, err := p.parseModule()
		if err != nil {
			return nil, err
		}
		file.Modules = append(file.Modules, mod)
	}

	return file, nil
}

func (p *Parser) parseModule() (*ast.Module, error) {
	if p.currTok.Type != token.IDENT {
		return nil, fmt.Errorf("line %d:%d: expected module name, got %q", p.currTok.Line, p.currTok.Col, p.currTok.Literal)
	}
	modName := p.currTok.Literal
	p.nextToken()

	if err := p.expect(token.DEFINITIONS); err != nil {
		return nil, err
	}

	tagDefault := "AUTOMATIC TAGS"
	if p.currTok.Type == token.AUTOMATIC {
		p.nextToken()
		if err := p.expect(token.TAGS); err != nil {
			return nil, err
		}
		tagDefault = "AUTOMATIC TAGS"
	}

	if err := p.expect(token.ASSIGN); err != nil {
		return nil, err
	}
	if err := p.expect(token.BEGIN); err != nil {
		return nil, err
	}

	mod := &ast.Module{
		Name:       modName,
		TagDefault: tagDefault,
	}

	// Parse EXPORTS if present
	if p.currTok.Type == token.EXPORTS {
		p.nextToken()
		for p.currTok.Type != token.SEMI && p.currTok.Type != token.EOF {
			if p.currTok.Type == token.IDENT {
				mod.Exports = append(mod.Exports, p.currTok.Literal)
			}
			p.nextToken()
		}
		if err := p.expect(token.SEMI); err != nil {
			return nil, err
		}
	}

	// Parse IMPORTS if present
	if p.currTok.Type == token.IMPORTS {
		p.nextToken()
		for p.currTok.Type != token.SEMI && p.currTok.Type != token.EOF {
			var symbols []string
			for p.currTok.Type != token.FROM && p.currTok.Type != token.SEMI && p.currTok.Type != token.EOF {
				if p.currTok.Type == token.IDENT {
					symbols = append(symbols, p.currTok.Literal)
				}
				p.nextToken()
			}
			if p.currTok.Type == token.FROM {
				p.nextToken()
				fromMod := p.currTok.Literal
				p.nextToken()
				mod.Imports = append(mod.Imports, &ast.Import{
					Symbols:    symbols,
					FromModule: fromMod,
				})
			}
		}
		if err := p.expect(token.SEMI); err != nil {
			return nil, err
		}
	}

	// Parse module assignments until END
	for p.currTok.Type != token.END && p.currTok.Type != token.EOF {
		identName := p.currTok.Literal
		p.nextToken()

		// Check if value assignment: ident INTEGER ::= val
		if p.currTok.Type == token.INTEGER && p.peekToken().Type == token.ASSIGN {
			p.nextToken() // INTEGER
			p.nextToken() // ::=
			val, err := strconv.ParseInt(p.currTok.Literal, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid integer constant %q", p.currTok.Line, p.currTok.Literal)
			}
			p.nextToken()
			mod.ValueAssignments = append(mod.ValueAssignments, &ast.ValueAssignment{
				Name:  identName,
				Type:  &ast.IntegerType{},
				Value: val,
			})
			continue
		}

		if err := p.expect(token.ASSIGN); err != nil {
			return nil, err
		}

		typ, err := p.parseType()
		if err != nil {
			return nil, fmt.Errorf("parsing type %s: %w", identName, err)
		}

		mod.TypeAssignments = append(mod.TypeAssignments, &ast.TypeAssignment{
			Name: identName,
			Type: typ,
		})
	}

	if err := p.expect(token.END); err != nil {
		return nil, err
	}

	return mod, nil
}

func (p *Parser) parseType() (ast.Type, error) {
	switch p.currTok.Type {
	case token.SEQUENCE:
		return p.parseSequenceOrSequenceOf()
	case token.CHOICE:
		return p.parseChoice()
	case token.ENUMERATED:
		return p.parseEnumerated()
	case token.INTEGER:
		return p.parseInteger()
	case token.BOOLEAN:
		p.nextToken()
		return &ast.BooleanType{}, nil
	case token.BIT:
		return p.parseBitString()
	case token.OCTET:
		return p.parseOctetString()
	case token.IA5String:
		return p.parseIA5String()
	case token.VisibleString:
		return p.parseVisibleString()
	case token.UTCTime:
		p.nextToken()
		return &ast.UTCTimeType{}, nil
	case token.NULL:
		p.nextToken()
		return &ast.NullType{}, nil
	case token.IDENT:
		name := p.currTok.Literal
		p.nextToken()
		return &ast.ReferenceType{Name: name}, nil
	default:
		return nil, fmt.Errorf("line %d:%d: unexpected token for type: %v (%q)", p.currTok.Line, p.currTok.Col, p.currTok.Type, p.currTok.Literal)
	}
}

func (p *Parser) parseSequenceOrSequenceOf() (ast.Type, error) {
	p.nextToken() // consume SEQUENCE

	// Check if SEQUENCE (SIZE (...)) OF Type or SEQUENCE SIZE (...) OF Type or SEQUENCE OF Type
	if p.currTok.Type == token.LPAREN || p.currTok.Type == token.SIZE || p.currTok.Type == token.OF {
		return p.parseSequenceOfRest()
	}

	if p.currTok.Type != token.LBRACE {
		return nil, fmt.Errorf("line %d: expected '{' after SEQUENCE, got %v (%q)", p.currTok.Line, p.currTok.Type, p.currTok.Literal)
	}
	p.nextToken() // consume '{'

	seq := &ast.SequenceType{}
	inExtensions := false

	for p.currTok.Type != token.RBRACE && p.currTok.Type != token.EOF {
		if p.currTok.Type == token.ELLIPSIS {
			seq.Extensible = true
			inExtensions = true
			p.nextToken()
			if p.currTok.Type == token.COMMA {
				p.nextToken()
			}
			continue
		}

		fieldName := p.currTok.Literal
		p.nextToken()

		fieldType, err := p.parseType()
		if err != nil {
			return nil, err
		}

		field := &ast.Field{
			Name: fieldName,
			Type: fieldType,
		}

		if p.currTok.Type == token.OPTIONAL {
			field.Optional = true
			p.nextToken()
		}

		if inExtensions {
			seq.ExtensionFields = append(seq.ExtensionFields, field)
		} else {
			seq.Fields = append(seq.Fields, field)
		}

		if p.currTok.Type == token.COMMA {
			p.nextToken()
		}
	}

	if err := p.expect(token.RBRACE); err != nil {
		return nil, err
	}
	return seq, nil
}

func (p *Parser) parseSequenceOfRest() (ast.Type, error) {
	seqOf := &ast.SequenceOfType{}

	if p.currTok.Type == token.LPAREN {
		p.nextToken() // (
		if err := p.expect(token.SIZE); err != nil {
			return nil, err
		}
		min, max, err := p.parseRangeConstraint()
		if err != nil {
			return nil, err
		}
		seqOf.HasSize = true
		seqOf.MinSizeStr = min
		seqOf.MaxSizeStr = max
		if err := p.expect(token.RPAREN); err != nil {
			return nil, err
		}
	} else if p.currTok.Type == token.SIZE {
		p.nextToken() // SIZE
		min, max, err := p.parseRangeConstraint()
		if err != nil {
			return nil, err
		}
		seqOf.HasSize = true
		seqOf.MinSizeStr = min
		seqOf.MaxSizeStr = max
	}

	if err := p.expect(token.OF); err != nil {
		return nil, err
	}

	elemType, err := p.parseType()
	if err != nil {
		return nil, err
	}
	seqOf.ElementType = elemType

	return seqOf, nil
}

func (p *Parser) parseChoice() (ast.Type, error) {
	p.nextToken() // consume CHOICE

	if err := p.expect(token.LBRACE); err != nil {
		return nil, err
	}

	choice := &ast.ChoiceType{}
	inExtensions := false

	for p.currTok.Type != token.RBRACE && p.currTok.Type != token.EOF {
		if p.currTok.Type == token.ELLIPSIS {
			choice.Extensible = true
			inExtensions = true
			p.nextToken()
			if p.currTok.Type == token.COMMA {
				p.nextToken()
			}
			continue
		}

		altName := p.currTok.Literal
		p.nextToken()

		altType, err := p.parseType()
		if err != nil {
			return nil, err
		}

		alt := &ast.Alternative{
			Name: altName,
			Type: altType,
		}

		if inExtensions {
			choice.ExtensionAlternatives = append(choice.ExtensionAlternatives, alt)
		} else {
			choice.Alternatives = append(choice.Alternatives, alt)
		}

		if p.currTok.Type == token.COMMA {
			p.nextToken()
		}
	}

	if err := p.expect(token.RBRACE); err != nil {
		return nil, err
	}
	return choice, nil
}

func (p *Parser) parseEnumerated() (ast.Type, error) {
	p.nextToken() // consume ENUMERATED

	if err := p.expect(token.LBRACE); err != nil {
		return nil, err
	}

	enum := &ast.EnumeratedType{}
	inExtensions := false

	for p.currTok.Type != token.RBRACE && p.currTok.Type != token.EOF {
		if p.currTok.Type == token.ELLIPSIS {
			enum.Extensible = true
			inExtensions = true
			p.nextToken()
			if p.currTok.Type == token.COMMA {
				p.nextToken()
			}
			continue
		}

		itemName := p.currTok.Literal
		p.nextToken()

		item := &ast.EnumItem{Name: itemName}
		if p.currTok.Type == token.LPAREN {
			p.nextToken()
			val, err := strconv.Atoi(p.currTok.Literal)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid enum value %q", p.currTok.Line, p.currTok.Literal)
			}
			item.Value = val
			item.HasValue = true
			p.nextToken()
			if err := p.expect(token.RPAREN); err != nil {
				return nil, err
			}
		}

		if inExtensions {
			enum.ExtensionItems = append(enum.ExtensionItems, item)
		} else {
			enum.Items = append(enum.Items, item)
		}

		if p.currTok.Type == token.COMMA {
			p.nextToken()
		}
	}

	if err := p.expect(token.RBRACE); err != nil {
		return nil, err
	}
	return enum, nil
}

func (p *Parser) parseInteger() (ast.Type, error) {
	p.nextToken() // consume INTEGER

	intType := &ast.IntegerType{}
	if p.currTok.Type == token.LPAREN {
		min, max, err := p.parseRangeConstraint()
		if err != nil {
			return nil, err
		}
		intType.IsConstrained = true
		intType.MinStr = min
		intType.MaxStr = max
	}

	return intType, nil
}

func (p *Parser) parseBitString() (ast.Type, error) {
	p.nextToken() // BIT
	if err := p.expect(token.STRING_KW); err != nil {
		return nil, err
	}

	bitType := &ast.BitStringType{}

	// Named bits check: { name(0), ... }
	if p.currTok.Type == token.LBRACE {
		p.nextToken()
		for p.currTok.Type != token.RBRACE && p.currTok.Type != token.EOF {
			name := p.currTok.Literal
			p.nextToken()
			if err := p.expect(token.LPAREN); err != nil {
				return nil, err
			}
			bitNum, err := strconv.Atoi(p.currTok.Literal)
			if err != nil {
				return nil, err
			}
			p.nextToken()
			if err := p.expect(token.RPAREN); err != nil {
				return nil, err
			}
			bitType.NamedBits = append(bitType.NamedBits, ast.NamedBit{Name: name, Bit: bitNum})
			if p.currTok.Type == token.COMMA {
				p.nextToken()
			}
		}
		if err := p.expect(token.RBRACE); err != nil {
			return nil, err
		}
	}

	// Size constraint check: (SIZE (...))
	if p.currTok.Type == token.LPAREN {
		p.nextToken()
		if err := p.expect(token.SIZE); err != nil {
			return nil, err
		}
		min, max, err := p.parseRangeConstraint()
		if err != nil {
			return nil, err
		}
		bitType.HasSize = true
		bitType.MinSizeStr = min
		bitType.MaxSizeStr = max
		if err := p.expect(token.RPAREN); err != nil {
			return nil, err
		}
	}

	return bitType, nil
}

func (p *Parser) parseOctetString() (ast.Type, error) {
	p.nextToken() // OCTET
	if err := p.expect(token.STRING_KW); err != nil {
		return nil, err
	}

	octetType := &ast.OctetStringType{}
	if p.currTok.Type == token.LPAREN {
		p.nextToken()
		if err := p.expect(token.SIZE); err != nil {
			return nil, err
		}
		min, max, err := p.parseRangeConstraint()
		if err != nil {
			return nil, err
		}
		octetType.HasSize = true
		octetType.MinSizeStr = min
		octetType.MaxSizeStr = max
		if err := p.expect(token.RPAREN); err != nil {
			return nil, err
		}
	}
	return octetType, nil
}

func (p *Parser) parseIA5String() (ast.Type, error) {
	p.nextToken() // IA5String
	charType := &ast.CharacterStringType{Kind: "IA5String"}

	if p.currTok.Type == token.LPAREN {
		p.nextToken()
		if err := p.expect(token.SIZE); err != nil {
			return nil, err
		}
		min, max, err := p.parseRangeConstraint()
		if err != nil {
			return nil, err
		}
		charType.HasSize = true
		charType.MinSizeStr = min
		charType.MaxSizeStr = max
		if err := p.expect(token.RPAREN); err != nil {
			return nil, err
		}
	}
	return charType, nil
}

func (p *Parser) parseVisibleString() (ast.Type, error) {
	p.nextToken() // VisibleString
	charType := &ast.CharacterStringType{Kind: "VisibleString"}

	// Could be (FROM (...)) or (SIZE (...)) or both
	for p.currTok.Type == token.LPAREN {
		p.nextToken()
		if p.currTok.Type == token.FROM {
			p.nextToken() // consume FROM
			if err := p.expect(token.LPAREN); err != nil {
				return nil, err
			}
			// parse alphabet items separated by |
			for p.currTok.Type != token.RPAREN && p.currTok.Type != token.EOF {
				if p.currTok.Type == token.STRING {
					firstStr := p.currTok.Literal
					p.nextToken()
					if p.currTok.Type == token.RANGE {
						p.nextToken() // ..
						secondStr := p.currTok.Literal
						p.nextToken()
						charType.Alphabet = append(charType.Alphabet, firstStr+"-"+secondStr)
					} else {
						charType.Alphabet = append(charType.Alphabet, firstStr)
					}
				}
				if p.currTok.Type == token.PIPE {
					p.nextToken()
				}
			}
			if err := p.expect(token.RPAREN); err != nil {
				return nil, err
			}
		} else if p.currTok.Type == token.SIZE {
			p.nextToken() // consume SIZE
			min, max, err := p.parseRangeConstraint()
			if err != nil {
				return nil, err
			}
			charType.HasSize = true
			charType.MinSizeStr = min
			charType.MaxSizeStr = max
		}
		if err := p.expect(token.RPAREN); err != nil {
			return nil, err
		}
	}

	return charType, nil
}

// parseRangeConstraint parses (min .. max) or (fixedVal).
func (p *Parser) parseRangeConstraint() (string, string, error) {
	if err := p.expect(token.LPAREN); err != nil {
		return "", "", err
	}

	minVal := p.currTok.Literal
	p.nextToken()

	if p.currTok.Type == token.RANGE {
		p.nextToken() // ..
		maxVal := p.currTok.Literal
		p.nextToken()
		if err := p.expect(token.RPAREN); err != nil {
			return "", "", err
		}
		return minVal, maxVal, nil
	}

	// Single fixed size (e.g. (64))
	if err := p.expect(token.RPAREN); err != nil {
		return "", "", err
	}
	return minVal, minVal, nil
}
