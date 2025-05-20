// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package codegen

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/DataDog/datadog-agent/pkg/dyninst/compiler/logical"
)

// tracker aggregates information about the final generated code, before it is generated.
type tracker struct {
	// PC of the first instruction of the function, used for call ops.
	functionLoc map[logical.FunctionID]uint32
}

// encodable is a code fragment that can be serialized into code byte sequence.
// Each code fragment must be able to declare apriori how many bytes it will
// generate.
type encodable interface {
	codeByteLen() uint32
	encode(e tracker, out io.Writer)
}

// functionComment is a code fragment that comments a function, itself containing no code.
type functionComment struct {
	id logical.FunctionID
}

func (f functionComment) codeByteLen() uint32 {
	return 0
}

func (f functionComment) encode(e tracker, out io.Writer) {
	fmt.Fprintf(out, "\t// 0x%x: %s\n", e.functionLoc[f.id], f.id.PrettyString())
}

// staticInstruction is a code fragment encoding logical ops, with all bytes known apriori.
type staticInstruction struct {
	name  string
	bytes []byte
}

func (i staticInstruction) codeByteLen() uint32 {
	// First byte is the op code.
	return 1 + uint32(len(i.bytes))
}

func (i staticInstruction) encode(e tracker, out io.Writer) {
	fmt.Fprintf(out, "\t\t%s, ", i.name)
	for _, b := range i.bytes {
		fmt.Fprintf(out, "0x%02x, ", b)
	}
	fmt.Fprintf(out, "\n")
}

// callInstruction is a custom code fragment for logical CallOp, requiring
// known code layout to encode itself.
type callInstruction struct {
	target logical.FunctionID
}

func (i callInstruction) codeByteLen() uint32 {
	return 1 + 4
}

func (i callInstruction) encode(e tracker, out io.Writer) {
	si := staticInstruction{
		name:  "SM_OP_CALL",
		bytes: binary.LittleEndian.AppendUint32(nil, e.functionLoc[i.target]),
	}
	if i.codeByteLen() != si.codeByteLen() {
		panic(fmt.Sprintf("callInstruction codeByteLen mismatch: %d != %d", i.codeByteLen(), si.codeByteLen()))
	}
	si.encode(e, out)
}

// generateCode generates:
//   - stack machine code
//   - type infos
func generateCode(program logical.Program, out io.Writer) error {
	t := tracker{
		functionLoc: make(map[logical.FunctionID]uint32, len(program.Functions)),
	}

	es := make([]encodable, 0)
	pc := uint32(0)
	append := func(e encodable) {
		es = append(es, e)
		pc += e.codeByteLen()
	}

	append(makeInstruction(logical.IllegalOp{}))

	for _, f := range program.Functions {
		t.functionLoc[f.ID] = pc
		append(functionComment{id: f.ID})
		for _, op := range f.Ops {
			append(makeInstruction(op))
		}
	}

	fmt.Fprintf(out, "const uint8_t stack_machine_code[] = {\n")
	for _, e := range es {
		e.encode(t, out)
	}
	fmt.Fprintf(out, "};\n\n")

	generateTypeInfos(program, t.functionLoc, out)
	return nil
}
