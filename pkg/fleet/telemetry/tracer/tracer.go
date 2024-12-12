// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package tracer provides a simple tracer for fleet components.
package tracer

import (
	"context"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type span struct {
	span ddtrace.Span
}

func (s *span) Finish(opts ...FinishOption) {
	var optsTracer []ddtrace.FinishOption
	for _, o := range opts {
		opts = append(opts, o)
	}
	s.span.Finish(optsTracer...)
}

func (s *span) SetTag(key string, value interface{}) {
	s.span.SetTag(key, value)
}

// Span represents a chunk of computation time. Spans have names, durations,
// timestamps and other metadata. A Tracer is used to create hierarchies of
// spans in a request, buffer and submit them to the server.
type Span interface {
	Finish(opts ...FinishOption)
	SetTag(key string, value interface{})
}

type FinishOption ddtrace.FinishOption

func WithError(err error) FinishOption {
	return FinishOption(tracer.WithError(err))
}

func StartSpanFromContext(ctx context.Context, operationName string) (Span, context.Context) {
	s, ctx := tracer.StartSpanFromContext(ctx, operationName)
	return &span{s}, ctx
}

func StartSpanFromRawContext(ctx context.Context, operationName string, traceID string, parentID string, priority string) (Span, context.Context) {
	ctxCarrier := tracer.TextMapCarrier{
		tracer.DefaultTraceIDHeader:  traceID,
		tracer.DefaultParentIDHeader: parentID,
		tracer.DefaultPriorityHeader: priority,
	}
	var s ddtrace.Span
	spanCtx, err := tracer.Extract(ctxCarrier)
	if err != nil {
		s, ctx = tracer.StartSpanFromContext(ctx, operationName)
	} else {
		s, ctx = tracer.StartSpanFromContext(ctx, operationName, tracer.ChildOf(spanCtx))
	}
	return &span{s}, ctx
}
