module github.com/DataDog/datadog-agent/comp/trace/compression/impl-zstd

go 1.22.0

replace github.com/DataDog/datadog-agent/comp/trace/compression/def => ../../../../comp/trace/compression/def/

require (
	github.com/DataDog/datadog-agent/comp/trace/compression/def v0.0.0-20250123182127-b55818e09cf4
	github.com/DataDog/zstd v1.5.6
)
