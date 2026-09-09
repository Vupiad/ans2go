package uper

import (
	"fmt"
	"math/bits"
)

// BitsNeeded calculates ceil(log2(rangeVal)), which is the number of bits
// needed to encode an unsigned integer in [0, rangeVal-1].
func BitsNeeded(rangeVal uint64) int {
	if rangeVal <= 1 {
		return 0
	}
	return bits.Len64(rangeVal - 1)
}

// OctetsNeeded calculates ceil(log256(rangeVal)), the maximum number of octets
// needed to represent values in [0, rangeVal-1].
func OctetsNeeded(rangeVal uint64) int {
	numBits := BitsNeeded(rangeVal)
	return (numBits + 7) / 8
}

// WriteConstrainedInt encodes a constrained whole number with bounds [lb, ub].
func (w *BitWriter) WriteConstrainedInt(val int64, lb int64, ub int64) error {
	if val < lb || val > ub {
		return fmt.Errorf("value %d out of bounds [%d, %d]", val, lb, ub)
	}
	if ub < lb {
		return fmt.Errorf("invalid bounds: lb %d > ub %d", lb, ub)
	}

	rangeVal := uint64(ub - lb + 1)
	offset := uint64(val - lb)

	if rangeVal == 1 {
		// 0 bits
		return nil
	}

	if rangeVal <= 65536 {
		numBits := BitsNeeded(rangeVal)
		w.WriteBits(offset, numBits)
		return nil
	}

	// Range is greater than 64K (ITU-T X.691 §12.2.6)
	maxOctets := OctetsNeeded(rangeVal)
	// Determine minimum number of octets needed for the offset value
	actualOctets := 1
	for temp := offset >> 8; temp > 0; temp >>= 8 {
		actualOctets++
	}
	if actualOctets > maxOctets {
		actualOctets = maxOctets
	}

	// Encode length of octet string as constrained whole number in range [1, maxOctets]
	lenBits := BitsNeeded(uint64(maxOctets))
	w.WriteBits(uint64(actualOctets-1), lenBits)

	// Encode offset as non-negative-binary-integer in actualOctets
	w.WriteBits(offset, actualOctets*8)
	return nil
}

// ReadConstrainedInt decodes a constrained whole number with bounds [lb, ub].
func (r *BitReader) ReadConstrainedInt(lb int64, ub int64) (int64, error) {
	if ub < lb {
		return 0, fmt.Errorf("invalid bounds: lb %d > ub %d", lb, ub)
	}
	rangeVal := uint64(ub - lb + 1)
	if rangeVal == 1 {
		return lb, nil
	}

	if rangeVal <= 65536 {
		numBits := BitsNeeded(rangeVal)
		val, err := r.ReadBits(numBits)
		if err != nil {
			return 0, err
		}
		return int64(val) + lb, nil
	}

	// Range is greater than 64K (ITU-T X.691 §12.2.6)
	maxOctets := OctetsNeeded(rangeVal)
	lenBits := BitsNeeded(uint64(maxOctets))
	lenOff, err := r.ReadBits(lenBits)
	if err != nil {
		return 0, err
	}
	actualOctets := int(lenOff) + 1
	if actualOctets > maxOctets {
		return 0, fmt.Errorf("decoded octet count %d exceeds max %d", actualOctets, maxOctets)
	}

	offset, err := r.ReadBits(actualOctets * 8)
	if err != nil {
		return 0, err
	}

	res := int64(offset) + lb
	if res > ub {
		return 0, fmt.Errorf("decoded value %d exceeds upper bound %d", res, ub)
	}
	return res, nil
}

// WriteNormallySmallNonNegativeWholeNumber encodes a normally small non-negative whole number (ITU-T X.691 §11.6).
func (w *BitWriter) WriteNormallySmallNonNegativeWholeNumber(n uint64) error {
	if n <= 63 {
		w.WriteBit(false)
		w.WriteBits(n, 6)
		return nil
	}
	w.WriteBit(true)
	return w.WriteSemiConstrainedInt(int64(n), 0)
}

// ReadNormallySmallNonNegativeWholeNumber decodes a normally small non-negative whole number (ITU-T X.691 §11.6).
func (r *BitReader) ReadNormallySmallNonNegativeWholeNumber() (uint64, error) {
	isLarge, err := r.ReadBit()
	if err != nil {
		return 0, err
	}
	if !isLarge {
		return r.ReadBits(6)
	}
	val, err := r.ReadSemiConstrainedInt(0)
	if err != nil {
		return 0, err
	}
	if val < 0 {
		return 0, fmt.Errorf("negative normally small value: %d", val)
	}
	return uint64(val), nil
}

// WriteSemiConstrainedInt encodes a semi-constrained whole number with lower bound lb.
func (w *BitWriter) WriteSemiConstrainedInt(val int64, lb int64) error {
	if val < lb {
		return fmt.Errorf("value %d < lower bound %d", val, lb)
	}
	offset := uint64(val - lb)
	octets := 1
	for temp := offset >> 8; temp > 0; temp >>= 8 {
		octets++
	}

	if err := w.WriteLengthDeterminant(octets); err != nil {
		return err
	}
	w.WriteBits(offset, octets*8)
	return nil
}

// ReadSemiConstrainedInt decodes a semi-constrained whole number with lower bound lb.
func (r *BitReader) ReadSemiConstrainedInt(lb int64) (int64, error) {
	octets, err := r.ReadLengthDeterminant()
	if err != nil {
		return 0, err
	}
	if octets <= 0 || octets > 8 {
		return 0, fmt.Errorf("unsupported octet count for integer: %d", octets)
	}
	val, err := r.ReadBits(octets * 8)
	if err != nil {
		return 0, err
	}
	return int64(val) + lb, nil
}
