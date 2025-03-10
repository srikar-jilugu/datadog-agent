// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/logs/message"
)

type JSONState int

const (
	Incomplete JSONState = iota
	Complete
	Invalid
)

type IncrementalJsonValidator struct {
	decoder      *json.Decoder
	writer       *bytes.Buffer
	resultBuffer *bytes.Buffer
	objCount     int
}

func NewIncrementalJsonValidator() *IncrementalJsonValidator {
	buf := &bytes.Buffer{}
	return &IncrementalJsonValidator{
		decoder:      json.NewDecoder(buf),
		writer:       buf,
		objCount:     0,
		resultBuffer: &bytes.Buffer{},
	}
}

func (d *IncrementalJsonValidator) Write(s []byte) JSONState {
	_, err := d.writer.Write(s)
	d.resultBuffer.Write([]byte(strings.TrimSpace(string(s))))

	if err != nil {
		return Invalid
	}

	for {
		t, err := d.decoder.Token()
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		}
		if err != nil {
			return Invalid
		}

		switch delim := t.(type) {
		case json.Delim:
			if delim.String() == "{" {
				d.objCount++
			}
			if delim.String() == "}" {
				d.objCount--
			}
		}
	}

	if d.objCount <= 0 {
		return Complete
	}
	return Incomplete
}

func (d *IncrementalJsonValidator) Flush() []byte {
	d.writer.Reset()
	d.decoder = json.NewDecoder(d.writer)
	d.objCount = 0
	outBuf := &bytes.Buffer{}
	_ = json.Compact(outBuf, d.resultBuffer.Bytes())
	defer d.resultBuffer.Reset()
	return outBuf.Bytes()
}

type JSONRecombinator struct {
	decoder    *IncrementalJsonValidator
	messageBuf []*message.Message
	flush      func(*message.Message)
}

func NewJSONRecombinator() *JSONRecombinator {
	return &JSONRecombinator{
		decoder:    NewIncrementalJsonValidator(),
		messageBuf: make([]*message.Message, 0),
	}
}

func (r *JSONRecombinator) Process(msg *message.Message) []*message.Message {
	switch r.decoder.Write(msg.GetContent()) {
	case Incomplete:
		r.messageBuf = append(r.messageBuf, msg)
	case Complete:
		msg.SetContent(r.decoder.Flush())
		r.messageBuf = r.messageBuf[:0]
		return []*message.Message{msg}
	case Invalid:
		_ = r.decoder.Flush()
		r.messageBuf = append(r.messageBuf, msg)
		msgs := r.messageBuf
		r.messageBuf = r.messageBuf[:0]
		return msgs
	}
	return nil
}
