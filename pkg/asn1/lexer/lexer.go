package lexer

import (
	"fmt"
	"unicode"

	"ans2go/pkg/asn1/token"
)

// Lexer tokenizes ASN.1 source text.
type Lexer struct {
	input   []rune
	pos     int
	readPos int
	ch      rune
	line    int
	col     int
}

// New creates a new Lexer for the given source input.
func New(input string) *Lexer {
	l := &Lexer{
		input: []rune(input),
		line:  1,
		col:   0,
	}
	l.readChar()
	return l
}

func (l *Lexer) readChar() {
	if l.readPos >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.readPos]
	}
	l.pos = l.readPos
	l.readPos++
	l.col++
}

func (l *Lexer) peekChar() rune {
	if l.readPos >= len(l.input) {
		return 0
	}
	return l.input[l.readPos]
}

func (l *Lexer) peekCharAhead(n int) rune {
	idx := l.readPos + n - 1
	if idx >= len(l.input) {
		return 0
	}
	return l.input[idx]
}

func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		if l.ch == '\n' {
			l.line++
			l.col = 0
		}
		l.readChar()
	}
}

func (l *Lexer) skipComment() {
	// Consumes from '--' to either the next '--' or end of line.
	// We are currently on the second '-'.
	l.readChar() // advance past second '-'

	for l.ch != 0 {
		if l.ch == '\n' {
			l.line++
			l.col = 0
			l.readChar()
			return
		}
		if l.ch == '-' && l.peekChar() == '-' {
			l.readChar() // past first '-'
			l.readChar() // past second '-'
			return
		}
		l.readChar()
	}
}

// NextToken returns the next token from the input.
func (l *Lexer) NextToken() token.Token {
	for {
		l.skipWhitespace()

		if l.ch == 0 {
			return token.Token{Type: token.EOF, Literal: "", Line: l.line, Col: l.col}
		}

		// Comment check: '--'
		if l.ch == '-' && l.peekChar() == '-' {
			l.skipComment()
			continue
		}

		break
	}

	startLine := l.line
	startCol := l.col

	switch l.ch {
	case ':':
		if l.peekChar() == ':' && l.peekCharAhead(2) == '=' {
			l.readChar()
			l.readChar()
			l.readChar()
			return token.Token{Type: token.ASSIGN, Literal: "::=", Line: startLine, Col: startCol}
		}
		tok := token.Token{Type: token.ILLEGAL, Literal: string(l.ch), Line: startLine, Col: startCol}
		l.readChar()
		return tok
	case '.':
		if l.peekChar() == '.' {
			if l.peekCharAhead(2) == '.' {
				l.readChar()
				l.readChar()
				l.readChar()
				return token.Token{Type: token.ELLIPSIS, Literal: "...", Line: startLine, Col: startCol}
			}
			l.readChar()
			l.readChar()
			return token.Token{Type: token.RANGE, Literal: "..", Line: startLine, Col: startCol}
		}
		tok := token.Token{Type: token.ILLEGAL, Literal: string(l.ch), Line: startLine, Col: startCol}
		l.readChar()
		return tok
	case '{':
		l.readChar()
		return token.Token{Type: token.LBRACE, Literal: "{", Line: startLine, Col: startCol}
	case '}':
		l.readChar()
		return token.Token{Type: token.RBRACE, Literal: "}", Line: startLine, Col: startCol}
	case '(':
		l.readChar()
		return token.Token{Type: token.LPAREN, Literal: "(", Line: startLine, Col: startCol}
	case ')':
		l.readChar()
		return token.Token{Type: token.RPAREN, Literal: ")", Line: startLine, Col: startCol}
	case '[':
		l.readChar()
		return token.Token{Type: token.LBRACKET, Literal: "[", Line: startLine, Col: startCol}
	case ']':
		l.readChar()
		return token.Token{Type: token.RBRACKET, Literal: "]", Line: startLine, Col: startCol}
	case ',':
		l.readChar()
		return token.Token{Type: token.COMMA, Literal: ",", Line: startLine, Col: startCol}
	case ';':
		l.readChar()
		return token.Token{Type: token.SEMI, Literal: ";", Line: startLine, Col: startCol}
	case '|':
		l.readChar()
		return token.Token{Type: token.PIPE, Literal: "|", Line: startLine, Col: startCol}
	case '"':
		str := l.readString()
		return token.Token{Type: token.STRING, Literal: str, Line: startLine, Col: startCol}
	case '-':
		// Negative number
		if unicode.IsDigit(l.peekChar()) {
			num := l.readNumber()
			return token.Token{Type: token.NUMBER, Literal: num, Line: startLine, Col: startCol}
		}
		tok := token.Token{Type: token.ILLEGAL, Literal: string(l.ch), Line: startLine, Col: startCol}
		l.readChar()
		return tok
	default:
		if unicode.IsDigit(l.ch) {
			num := l.readNumber()
			return token.Token{Type: token.NUMBER, Literal: num, Line: startLine, Col: startCol}
		} else if isIdentStart(l.ch) {
			ident := l.readIdentifier()
			tokType := token.LookupIdent(ident)
			return token.Token{Type: tokType, Literal: ident, Line: startLine, Col: startCol}
		}
		ch := l.ch
		l.readChar()
		return token.Token{Type: token.ILLEGAL, Literal: string(ch), Line: startLine, Col: startCol}
	}
}

func isIdentStart(ch rune) bool {
	return unicode.IsLetter(ch)
}

func isIdentPart(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '-' || ch == '_'
}

func (l *Lexer) readIdentifier() string {
	start := l.pos
	for isIdentPart(l.ch) {
		// Note: in ASN.1, a hyphen cannot be followed immediately by another hyphen
		if l.ch == '-' && l.peekChar() == '-' {
			break
		}
		l.readChar()
	}
	// If trailing hyphen, step back (identifiers cannot end in hyphen)
	if l.pos > start && l.input[l.pos-1] == '-' {
		// step back
		l.pos--
		l.readPos--
		l.col--
		l.ch = l.input[l.pos]
	}
	return string(l.input[start:l.pos])
}

func (l *Lexer) readNumber() string {
	start := l.pos
	if l.ch == '-' {
		l.readChar()
	}
	for unicode.IsDigit(l.ch) {
		l.readChar()
	}
	return string(l.input[start:l.pos])
}

func (l *Lexer) readString() string {
	l.readChar() // skip opening quote
	start := l.pos
	for l.ch != '"' && l.ch != 0 {
		l.readChar()
	}
	str := string(l.input[start:l.pos])
	if l.ch == '"' {
		l.readChar() // skip closing quote
	}
	return str
}

// TokenizeAll helper to tokenize an entire input string into a slice of tokens.
func TokenizeAll(input string) ([]token.Token, error) {
	lex := New(input)
	var tokens []token.Token
	for {
		tok := lex.NextToken()
		if tok.Type == token.ILLEGAL {
			return nil, fmt.Errorf("lexical error at line %d col %d: illegal character %q", tok.Line, tok.Col, tok.Literal)
		}
		tokens = append(tokens, tok)
		if tok.Type == token.EOF {
			break
		}
	}
	return tokens, nil
}
