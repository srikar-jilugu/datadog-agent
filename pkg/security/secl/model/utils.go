// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package model holds model related files
package model

import (
	"bytes"
	"encoding/binary"
)

// SliceToArray copy src bytes to dst. Destination should have enough space
func SliceToArray(src []byte, dst []byte) {
	if len(src) != len(dst) {
		panic("different len in SliceToArray")
	}

	copy(dst, src)
}

// UnmarshalStringArray extract array of string for array of byte
func UnmarshalStringArray(data []byte) ([]string, error) {
	length := uint32(len(data))

	prealloc := 0
	for i := uint32(0); i < length; {
		if i+4 >= length {
			break
		}
		// size of arg
		n := binary.NativeEndian.Uint32(data[i : i+4])
		if n == 0 {
			break
		}
		i += 4
		i += n
		prealloc++
	}

	result := make([]string, 0, prealloc)

	for i := uint32(0); i < length; {
		if i+4 >= length {
			return result, ErrStringArrayOverflow
		}
		// size of arg
		n := binary.NativeEndian.Uint32(data[i : i+4])
		if n == 0 {
			return result, nil
		}
		i += 4

		if i+n > length {
			// truncated
			arg := NullTerminatedString(data[i:length])
			return append(result, arg), ErrStringArrayOverflow
		}

		arg := NullTerminatedString(data[i : i+n])
		i += n

		result = append(result, arg)
	}

	return result, nil
}

// UnmarshalString unmarshal string
func UnmarshalString(data []byte, size int) (string, error) {
	if len(data) < size {
		return "", ErrNotEnoughData
	}

	return NullTerminatedString(data[:size]), nil
}

// NullTerminatedString returns null-terminated string
func NullTerminatedString(d []byte) string {
	idx := bytes.IndexByte(d, 0)
	if idx == -1 {
		return string(d)
	}
	return string(d[:idx])
}

// UnmarshalPrintableString unmarshal printable string
func UnmarshalPrintableString(data []byte, size int) (string, error) {
	if len(data) < size {
		return "", ErrNotEnoughData
	}

	str, err := UnmarshalString(data, size)
	if err != nil {
		return "", err
	}
	if !IsPrintable(str) {
		return "", ErrNonPrintable
	}

	return str, nil
}
