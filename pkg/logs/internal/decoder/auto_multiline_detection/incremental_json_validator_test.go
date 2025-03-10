// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package automultilinedetection contains auto multiline detection and aggregation logic.
package automultilinedetection

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoder(t *testing.T) {
	decoder := NewIncrementalJsonValidator()
	assert.Equal(t, Incomplete, decoder.Write([]byte(`{"foo":`)))
	assert.Equal(t, Incomplete, decoder.Write([]byte(`"bar"`)))
	assert.Equal(t, Complete, decoder.Write([]byte(`}`)))
	assert.Equal(t, `{"foo":"bar"}`, string(decoder.Flush()))

	assert.Equal(t, Incomplete, decoder.Write([]byte(`{   `)))
	assert.Equal(t, Incomplete, decoder.Write([]byte(`"foo"`)))
	assert.Equal(t, Incomplete, decoder.Write([]byte(`:"bar"`)))
	assert.Equal(t, Complete, decoder.Write([]byte(`}`)))
	decoder.Flush()

	assert.Equal(t, Incomplete, decoder.Write([]byte(`{   `)))
	assert.Equal(t, Incomplete, decoder.Write([]byte(`"foo":  `)))
	assert.Equal(t, Incomplete, decoder.Write([]byte(`{"foo":`)))
	assert.Equal(t, Incomplete, decoder.Write([]byte(`"bar nested"`)))
	assert.Equal(t, Incomplete, decoder.Write([]byte(`}`)))
	assert.Equal(t, Complete, decoder.Write([]byte(`}`)))
	decoder.Flush()

	nested := `
		{
	    "clusters_table": [
	        {
	            "score": 1317,
	            "weight": 1.1083363,
	            "sample_count": 1189,
	            "tokens": "DDDD-DD-DD DD:DD:DD,DDD - CCCC - CCCCC -",
	            "sample": "2024-04-24 16:29:02,304 - root - DEBUG -"
	        }
	    ]
	}
	`
	assert.Equal(t, Complete, decoder.Write([]byte(nested)))
	fmt.Println(string(decoder.Flush()))

	largeJson := `
		{
	    "id": "565290f7-6ce0-4d3d-be7f-685905c27f04",
	    "clusters": 6,
	    "samples": 1301,
	    "dropped_clusters": 0,
	    "detected_multi_line_log": true,
	    "mixed_format_likely": false,
	    "is_json": false,
	    "confidence": 1.1082453,
	    "top_match": {
	        "score": 1317,
	        "weight": 1.1083363,
	        "sample_count": 1189,
	        "tokens": "DDDD-DD-DD DD:DD:DD,DDD - CCCC - CCCCC -",
	        "sample": "2024-04-24 16:29:02,304 - root - DEBUG -"
	    },
	    "clusters_table": [
	        {
	            "score": 1317,
	            "weight": 1.1083363,
	            "sample_count": 1189,
	            "tokens": "DDDD-DD-DD DD:DD:DD,DDD - CCCC - CCCCC -",
	            "sample": "2024-04-24 16:29:02,304 - root - DEBUG -"
	        },
	        {
	            "score": 9,
	            "weight": 0.1875589,
	            "sample_count": 48,
	            "tokens": " CCCC \"/./CCCC.CC\", CCCC DD, CC CCCCCC",
	            "sample": "  File \"//./main.py\", line 34, in <modul"
	        },
	        {
	            "score": 8,
	            "weight": 0.18262392,
	            "sample_count": 40,
	            "tokens": " CCC C(): C() ",
	            "sample": "    def a(): b()\r"
	        },
	        {
	            "score": 3,
	            "weight": 0.2999901,
	            "sample_count": 8,
	            "tokens": "CCCCCCCCC: CCCC 'C' CC CCC CCCCCCC ",
	            "sample": "NameError: name 'g' is not defined\r"
	        },
	        {
	            "score": 1,
	            "weight": 0.1,
	            "sample_count": 8,
	            "tokens": "CCCCCCCCC (CCCC CCCCCC CCCC CCCC): ",
	            "sample": "Traceback (most recent call last):\r"
	        },
	        {
	            "score": 1,
	            "weight": 0.1,
	            "sample_count": 8,
	            "tokens": " C() ",
	            "sample": "    a()\r"
	        }
	    ]
	}
	`
	assert.Equal(t, Complete, decoder.Write([]byte(largeJson)))
	fmt.Println(string(decoder.Flush()))

	// lines := strings.Split(largeJson, "\n")
	// for _, line := range lines {
	// 	fmt.Println("LINE", line)
	// 	r := decoder.Write([]byte(line))
	// 	if r == Complete {
	// 		fmt.Println("INCOMPLETE")
	// 	}
	// }
	// fmt.Println(string(decoder.Flush()))

}
