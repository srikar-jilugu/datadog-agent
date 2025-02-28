//go:build linux_bpf

package trace

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type Span struct {
	TraceId_l     uint64
	SpanId        uint64
	ParentId      uint64
	Service       string
	Name          string
	Resource_name string
	SpanType      string
	meta          map[string]string
	metrics       map[string]float32
}

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
