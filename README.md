# ans2go: ASN.1 to Go Compiler & UPER Codec

**ans2go** is a high-performance ASN.1 compiler and ITU-T X.691 **UPER (Unaligned Packed Encoding Rules)** codec generator written in Go.

It compiles ASN.1 specifications into clean, idiomatic, type-safe Go structs and generates direct, **zero-reflection** `EncodeUPER` and `DecodeUPER` methods. It was designed and verified against the complete **OMA UserPlane Location Protocol (SUPL v1 & v2)** specification suite.

---

## Key Features

- **Complete ASN.1 Frontend**:
  - Multi-module files (e.g., handles 17+ modules in a single `.asn` file).
  - Full support for `AUTOMATIC TAGS`, `IMPORTS`, `EXPORTS`, and cross-module cyclic dependencies.
  - Constrained & semi-constrained types (`INTEGER`, `BIT STRING`, `OCTET STRING`, `IA5String`, `VisibleString`, `UTCTime`, `NULL`).
  - Constant folding in bounds (e.g., `INTEGER (1..maxNumGeoArea)`).
  - Automatic promotion of inline anonymous `SEQUENCE`, `CHOICE`, `ENUMERATED`, and `SEQUENCE OF` into first-class named Go types.
- **Strict ITU-T X.691 UPER Compliance**:
  - Unaligned bit packing without wasteful padding.
  - Integer range optimization ($\lceil \log_2 R \rceil$ bits for $R \le 65536$; length determinant + binary octets for $R > 65536$).
  - Extensible `SEQUENCE` and `CHOICE` types with extension bits, presence bitmaps, and Open Type encapsulation.
  - Normally small non-negative whole numbers (§11.6) and length determinants (§11.9).
  - Effective alphabet mapping for `VisibleString` (e.g., FQDN 64-character alphabet packed into 6 bits/character).
- **Zero-Reflection Performance**:
  - Direct bitstream operations for serialization and deserialization.
  - Benchmarks execute in microseconds with minimal heap allocations.
- **Idiomatic Go API**:
  - Pointer semantics for `OPTIONAL` and extension addition fields.
  - Tagged union structs for `CHOICE` alternatives (no messy `interface{}` type assertions required).
  - Strongly typed `int` enums with named constants for `ENUMERATED`.

---

## Project Structure

```
.
├── cmd/
│   └── ans2go/              # Compiler CLI driver (main.go)
├── example/                 # Example specifications & generated packages
│   ├── ilp/                 # OMA ILP specification & generated package
│   │   ├── ILP.asn          # 11 modules
│   │   ├── ILP-Components.asn # 1 module
│   │   ├── types.go         # Generated types (197 types, 313 KB)
│   │   └── ilp_test.go      # Roundtrip tests
│   └── supl1/               # OMA SUPL v1 & v2 specification & generated package
│       ├── ULP.asn          # 1 module (ULP)
│       ├── SUPL.asn         # 17 modules (SUPL-INIT, SUPL-START, etc.)
│       ├── ULP-Components.asn # 2 modules (ULP-Components, Ver2-ULP-Components)
│       ├── types.go         # Generated types (262 types, 428 KB)
│       └── supl1_test.go    # Comprehensive roundtrip tests
└── pkg/
    ├── asn1/                # Compiler Frontend
    │   ├── token/           # Token definitions
    │   ├── lexer/           # High-speed ASN.1 lexer
    │   ├── ast/             # AST node definitions
    │   ├── parser/          # Recursive descent parser
    │   └── analyzer/        # Semantic analyzer & constant resolver
    ├── generator/           # Go code & UPER codec emitter
    └── uper/                # ITU-T X.691 UPER runtime library
        ├── bitstream.go     # BitReader & BitWriter
        ├── integers.go      # Constrained integer codecs
        ├── lengths.go       # Length determinants & Open Type
        ├── strings.go       # String & BitString codecs
        └── types.go         # Core types and interfaces
```

---

## Installation & Build

### Prerequisites
- Go 1.21 or higher (tested with Go 1.23).

### Build the Compiler Binary
```bash
# Build the ans2go executable in the project root
go build -o ans2go ./cmd/ans2go
```

Alternatively, install it to your `$GOPATH/bin`:
```bash
go install ./cmd/ans2go
```

---

## CLI Usage

Run `ans2go` by pointing it to the folder containing your ASN.1 files:

```bash
./ans2go -dir <input_dir> [-o <output_dir>] [-pkg <package_name>]
```

### Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-dir` | `example/supl1` | Directory containing `.asn` specification files |
| `-o` | `<input_dir>` | Destination directory for generated Go code (`types.go`). Defaults to the input directory (`-dir`) |
| `-pkg` | `<folder_name>` | Name of the generated Go package. **Defaults to the input folder name** (e.g., `supl1` or `ilp`) |

### Example 1: Compiling SUPL Specifications (`example/supl1`)

```bash
./ans2go -dir example/supl1
```

Output:
```
2026/09/09 11:22:27 ans2go ASN.1 Compiler starting...
2026/09/09 11:22:27 Scanning directory: example/supl1
2026/09/09 11:22:27 Target package name: supl1
2026/09/09 11:22:27 Output directory: example/supl1
2026/09/09 11:22:27 Parsed SUPL.asn: 17 modules
2026/09/09 11:22:27 Parsed ULP-Components.asn: 2 modules
2026/09/09 11:22:27 Parsed ULP.asn: 1 modules
2026/09/09 11:22:27 Analysis complete: 15 constants, 262 types defined
2026/09/09 11:22:27 Successfully generated example/supl1/types.go (428803 bytes)
Done. Generated 262 types into example/supl1/types.go (package supl1)
```

### Example 2: Compiling ILP Specifications (`example/ilp`)

```bash
./ans2go -dir example/ilp
```

Output:
```
2026/09/09 11:22:27 ans2go ASN.1 Compiler starting...
2026/09/09 11:22:27 Scanning directory: example/ilp
2026/09/09 11:22:27 Target package name: ilp
2026/09/09 11:22:27 Output directory: example/ilp
2026/09/09 11:22:27 Parsed ILP-Components.asn: 1 modules
2026/09/09 11:22:27 Parsed ILP.asn: 11 modules
2026/09/09 11:22:27 Analysis complete: 11 constants, 197 types defined
2026/09/09 11:22:27 Successfully generated example/ilp/types.go (313359 bytes)
Done. Generated 197 types into example/ilp/types.go (package ilp)
```

---

## How to Use the Generated Go Code

### 1. High-Level API: `Marshal` and `Unmarshal`

The generated package provides top-level `Marshal` and `Unmarshal` functions:

```go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"ans2go/example/supl1"
)

func main() {
	// 1. Construct an ASN.1 message (e.g. ULP-PDU with SUPLSTART)
	pdu := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SetSessionID: &supl1.SetSessionID{
				SessionId: 1001,
				SetId: supl1.SETId{
					Choice: supl1.SETIdChoice_Msisdn,
					Msisdn: ptr([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}),
				},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLSTART,
			MsSUPLSTART: &supl1.SUPLSTART{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{
						AgpsSETassisted: true,
						AutonomousGPS:   true,
					},
					PrefMethod: supl1.PrefMethod_AgpsSETassistedPreferred,
					PosProtocol: supl1.PosProtocol{
						Rrlp: true,
					},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 460,
							RefMNC: 1,
							RefLAC: 1024,
							RefCI:  2048,
							TA:     ptr(int64(5)),
						},
					},
				},
			},
		},
	}

	// 2. Encode to UPER byte slice
	data, err := supl1.Marshal(&pdu)
	if err != nil {
		log.Fatalf("UPER encode error: %v", err)
	}
	fmt.Printf("Encoded UPER (%d bytes): %s\n", len(data), hex.EncodeToString(data))

	// 3. Decode from UPER byte slice
	var decoded supl1.ULPPDU
	if err := supl1.Unmarshal(data, &decoded); err != nil {
		log.Fatalf("UPER decode error: %v", err)
	}

	// 4. Access fields
	fmt.Printf("Decoded SessionID: %d\n", decoded.SessionID.SetSessionID.SessionId)
	if decoded.Message.Choice == supl1.UlpMessageChoice_MsSUPLSTART {
		gsm := decoded.Message.MsSUPLSTART.LocationId.CellInfo.GsmCell
		fmt.Printf("Cell: MCC=%d MNC=%d LAC=%d CI=%d\n", gsm.RefMCC, gsm.RefMNC, gsm.RefLAC, gsm.RefCI)
	}
}

func ptr[T any](v T) *T { return &v }
```

---

## Type Mapping Reference

### 1. `SEQUENCE`
Mapped to a Go `struct`:
- Mandatory fields $\rightarrow$ value types (or pointers for large nested objects).
- `OPTIONAL` fields $\rightarrow$ pointer types (`*T`). Set to `nil` when absent.
- Extension additions (fields following `...`) $\rightarrow$ pointer types (`*T`).

```go
type GsmCellInformation struct {
	RefMCC int64
	RefMNC int64
	RefLAC int64
	RefCI  int64
	NMR    *NMR   // OPTIONAL
	TA     *int64 // OPTIONAL
}
```

### 2. `CHOICE`
Mapped to a **Tagged Struct** containing a `Choice` selector and pointers for each alternative:

```go
type SLPAddressChoice int

const (
	SLPAddressChoice_None      SLPAddressChoice = 0
	SLPAddressChoice_IPAddress SLPAddressChoice = 1
	SLPAddressChoice_FQDN      SLPAddressChoice = 2
)

type SLPAddress struct {
	Choice    SLPAddressChoice
	IPAddress *IPAddress
	FQDN      *FQDN
}
```

To instantiate a `CHOICE`:
```go
addr := supl.SLPAddress{
	Choice: supl.SLPAddressChoice_FQDN,
	FQDN:   ptr(supl.FQDN("slp.location.operator.com")),
}
```

### 3. `ENUMERATED`
Mapped to a typed Go `int` with constants:

```go
type StatusCode int

const (
	StatusCode_Unspecified      StatusCode = 0
	StatusCode_SystemFailure    StatusCode = 1
	StatusCode_UnexpectedMessage StatusCode = 2
	StatusCode_ResourceShortage StatusCode = 11
	// ...
)
```

### 4. `SEQUENCE OF`
Mapped to a Go slice of the element type:

```go
// ASN.1: MultipleLocationIds ::= SEQUENCE SIZE (1..64) OF LocationIdData
type MultipleLocationIds []LocationIdData
```

### 5. `BIT STRING`
Mapped to `uper.BitString`:
```go
type BitString struct {
	Bytes     []byte
	BitLength int
}

// Helpers:
bs := uper.NewBitString([]byte{0xA0}, 4) // '1010'B
bit0 := bs.GetBit(0) // true
bs.SetBit(1, true)   // '1110'B
```

### 6. `OCTET STRING`
Mapped directly to `[]byte`. When `OPTIONAL`, mapped to `*[]byte` for unambiguous presence detection.

---

## Running Tests

Run the complete test suite across all packages:

```bash
go test -v ./...
```

To run without caching:
```bash
go test -count=1 ./...
```

### Test Coverage Highlights
- [`pkg/uper/uper_test.go`](file:///home/vupiad/pet-project/ans2go/pkg/uper/uper_test.go): BitWriter/BitReader, constrained integers, normally small numbers, Open Types, bit strings, alphabet-constrained strings.
- [`pkg/asn1/lexer/lexer_test.go`](file:///home/vupiad/pet-project/ans2go/pkg/asn1/lexer/lexer_test.go): Lexer verification on all `.asn` files.
- [`pkg/asn1/parser/parser_test.go`](file:///home/vupiad/pet-project/ans2go/pkg/asn1/parser/parser_test.go): Parser verification across 20 modules.
- [`pkg/asn1/analyzer/analyzer_test.go`](file:///home/vupiad/pet-project/ans2go/pkg/asn1/analyzer/analyzer_test.go): Constant folding and anonymous type lifting.
- [`example/supl1/supl1_test.go`](file:///home/vupiad/pet-project/ans2go/example/supl1/supl1_test.go): End-to-end SUPL v1 & v2 roundtrip encoding and decoding (`SUPLINIT`, `SUPLSTART`, `SUPLEND`, extensions, choices).
- [`example/ilp/ilp_test.go`](file:///home/vupiad/pet-project/ans2go/example/ilp/ilp_test.go): End-to-end ILP roundtrip encoding and decoding (`IPAddress`, `SessionID2`).

---

## License
MIT License.

