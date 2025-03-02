//go:build linux_bpf

//go:generate msgp -unexported -tests=false
//msgp:ignore writer

package trace

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/tinylib/msgp/msgp"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type Span struct {
	TraceId_l uint64             `msg:"trace_id"`
	SpanId    uint64             `msg:"span_id"`
	ParentId  uint64             `msg:"parent_id"`
	Service   string             `msg:"service"`
	Name      string             `msg:"name"`
	Start     int64              `msg:"start"`
	Duration  int64              `msg:"duration"`
	Resource  string             `msg:"resource"`
	SpanType  string             `msg:"type"`
	Meta      map[string]string  `msg:"meta,omitempty"`
	Metrics   map[string]float64 `msg:"metrics,omitempty"`
}

type (
	// spanList implements msgp.Encodable on top of a slice of spans.
	spanList []*Span

	// spanLists implements msgp.Decodable on top of a slice of spanList.
	// This type is only used in tests.
	spanLists []spanList
)

var (
	_ msgp.Encodable = (*spanList)(nil)
	_ msgp.Encodable = (*spanLists)(nil)
)

var trace_writer writer

type writer struct {
	mux    sync.Mutex
	ticker time.Ticker
	chunks map[uint64][]Span
	spans  chan Span
	done   chan bool
}

func (w *writer) flush(chunk map[uint64][]Span) {
	if len(chunk) <= 0 {
		return
	}
	log.Infof("Flushing chunk of %+v traces", chunk)

	var spanLists spanLists
	for _, spans := range chunk {
		var spanList []*Span
		for _, s := range spans {
			spanList = append(spanList, &s)
		}
		spanLists = append(spanLists, spanList)
	}

	bts, _ := spanLists.MarshalMsg(nil)

	// Create a new PUT request
	req, err := http.NewRequest("PUT", "http://localhost:8126/v0.4/traces", bytes.NewBuffer(bts))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set the content type header
	req.Header.Set("Content-Type", "application/msgpack")
	req.Header.Set("Datadog-Meta-Lang", "ebpf")
	req.Header.Set("X-Datadog-Trace-Count", strconv.Itoa(len(chunk)))

	req.Header.Set("Datadog-Meta-Lang-Version", "0.0.1")
	req.Header.Set("Datadog-Meta-Lang-Interpreter", "beyla")
	req.Header.Set("Datadog-Meta-Tracer-Version", "0.1.0")

	// Create a new HTTP client
	client := &http.Client{}

	// Send the PUT request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Print the response status and body
	fmt.Println("Response Status:", resp.Status)
	fmt.Println("Response Body:", string(body))

}

func Init() {
	trace_writer = writer{
		ticker: *time.NewTicker(5 * time.Second),
		chunks: make(map[uint64][]Span),
		spans:  make(chan Span, 1000),
		done:   make(chan bool),
	}

	go func() {
		for {
			select {
			case s := <-trace_writer.spans:
				trace_writer.mux.Lock()
				if _, ok := trace_writer.chunks[s.TraceId_l]; !ok {
					trace_writer.chunks[s.TraceId_l] = []Span{}
				}
				trace_writer.chunks[s.TraceId_l] = append(trace_writer.chunks[s.TraceId_l], s)
				trace_writer.mux.Unlock()
				log.Tracef("Enqueued a new span %v", s)
			case <-trace_writer.ticker.C:
				trace_writer.mux.Lock()
				to_be_sent := trace_writer.chunks
				trace_writer.chunks = make(map[uint64][]Span)
				trace_writer.mux.Unlock()
				go trace_writer.flush(to_be_sent)
			case <-trace_writer.done:
				return
			}
		}
	}()
}

func Stop() {
	trace_writer.done <- true
}

func Record(span Span) {
	trace_writer.spans <- span
}
