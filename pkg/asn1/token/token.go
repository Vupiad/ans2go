package token

// TokenType represents a lexical token type in ASN.1.
type TokenType int

const (
	ILLEGAL TokenType = iota
	EOF
	COMMENT

	// Literals & Identifiers
	IDENT  // Version, SessionID, Ver2-CellInfo-extension
	NUMBER // 123, -8388608
	STRING // "a", ".-"

	// Delimiters and operators
	ASSIGN   // ::=
	ELLIPSIS // ...
	RANGE    // ..
	LBRACE   // {
	RBRACE   // }
	LPAREN   // (
	RPAREN   // )
	LBRACKET // [
	RBRACKET // ]
	COMMA    // ,
	SEMI     // ;
	PIPE     // |

	// Keywords
	DEFINITIONS
	AUTOMATIC
	TAGS
	BEGIN
	END
	IMPORTS
	EXPORTS
	FROM
	SEQUENCE
	OF
	CHOICE
	ENUMERATED
	INTEGER
	BOOLEAN
	BIT
	OCTET
	STRING_KW
	IA5String
	VisibleString
	UTCTime
	NULL
	SIZE
	OPTIONAL
	DEFAULT
)

var keywords = map[string]TokenType{
	"DEFINITIONS":   DEFINITIONS,
	"AUTOMATIC":     AUTOMATIC,
	"TAGS":          TAGS,
	"BEGIN":         BEGIN,
	"END":           END,
	"IMPORTS":       IMPORTS,
	"EXPORTS":       EXPORTS,
	"FROM":          FROM,
	"SEQUENCE":      SEQUENCE,
	"OF":            OF,
	"CHOICE":        CHOICE,
	"ENUMERATED":    ENUMERATED,
	"INTEGER":       INTEGER,
	"BOOLEAN":       BOOLEAN,
	"BIT":           BIT,
	"OCTET":         OCTET,
	"STRING":        STRING_KW,
	"IA5String":     IA5String,
	"VisibleString": VisibleString,
	"UTCTime":       UTCTime,
	"NULL":          NULL,
	"SIZE":          SIZE,
	"OPTIONAL":      OPTIONAL,
	"DEFAULT":       DEFAULT,
}

// LookupIdent checks if an identifier is a reserved ASN.1 keyword.
func LookupIdent(ident string) TokenType {
	if tok, ok := keywords[ident]; ok {
		return tok
	}
	return IDENT
}

// Token represents a token and its source position.
type Token struct {
	Type   TokenType
	Literal string
	Line   int
	Col    int
}
