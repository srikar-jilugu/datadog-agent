module github.com/DataDog/datadog-agent/pkg/tagger/types

go 1.22.0

replace github.com/DataDog/datadog-agent/comp/core/tagger/origindetection => ../../../comp/core/tagger/origindetection

require github.com/DataDog/datadog-agent/comp/core/tagger/origindetection v0.0.0-20250123092007-9394a87c7579
