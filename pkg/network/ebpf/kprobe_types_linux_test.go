package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type ProtocolStackWrapperWithPadding struct {
	Stack   ProtocolStack
	_       [4]byte // Explicit padding (4 bytes to match C layout)
	Updated uint64
}

func TestBinaryReadProtocolStackWrapper(t *testing.T) {
	// Simulating the C memory layout (with padding)
	cBuffer := []byte{
		1, 2, 0, 4, // ProtocolStack (4 bytes)
		0, 0, 0, 0, // Padding (4 bytes)
		0x15, 0xCD, 0x5B, 0x07, 0x00, 0x00, 0x00, 0x00, // Updated (8 bytes) = 123456789
	}

	// 1. Attempt to read without handling padding (should FAIL)
	var noPadding ProtocolStackWrapper
	r := bytes.NewReader(cBuffer)
	err := binary.Read(r, binary.LittleEndian, &noPadding)
	if err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}

	if noPadding.Updated == 123456789 {
		t.Errorf("Incorrect deserialization (no padding): %+v", noPadding)
	} else {
		t.Logf("Deserialization failed as expected (no padding): %+v", noPadding)
	}

	// 2. Attempt to read with padding (should PASS)
	var withPadding ProtocolStackWrapperWithPadding

	r = bytes.NewReader(cBuffer) // Reset reader
	err = binary.Read(r, binary.LittleEndian, &withPadding)
	if err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}

	if withPadding.Updated != 123456789 {
		t.Errorf("Incorrect deserialization (with padding): %+v", withPadding)
	} else {
		t.Logf("Deserialization with padding: %+v", withPadding)
	}
}
