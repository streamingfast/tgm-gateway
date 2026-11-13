module github.com/streamingfast/payment-gateway

go 1.26.0

require (
	connectrpc.com/connect v1.18.1
	github.com/lestrrat-go/jwx/v3 v3.0.10
	github.com/streamingfast/dauth v0.0.0-20261104193507-69230e98d89e
	github.com/streamingfast/derr v0.0.0-20250814163534-bd7407bd89d7
	github.com/streamingfast/dgrpc v0.0.0-20251218133127-15b36e02a74f
	github.com/streamingfast/dmetering v0.0.0-20251027175535-4fd530934b97
	github.com/streamingfast/dmetrics v0.0.0-20250711072030-f023e918a175
	github.com/streamingfast/dsession v0.0.0-20251029144057-b94d1030e142
	github.com/streamingfast/shutter v1.5.0
	github.com/streamingfast/worker-pool-protocol v0.0.0-20251029142144-b539534f3eb1
	github.com/stretchr/testify v1.12.1
	go.uber.org/zap v1.27.0
	golang.org/x/oauth2 v0.36.0
	google.golang.org/grpc v1.82.1
	google.golang.org/protobuf v1.36.11
)

require (
	cloud.google.com/go/auth v0.16.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/trace v1.11.6 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.32.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace v1.29.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.53.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blendle/zapdriver v1.3.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.37.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.14.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.2 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.0 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/openzipkin/zipkin-go v0.4.2 // indirect
	github.com/paulbellamy/ratecounter v0.2.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/prometheus/client_golang v1.21.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.16.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/sercand/kuberesolver/v5 v5.1.1 // indirect
	github.com/sethvargo/go-retry v0.2.3 // indirect
	github.com/spiffe/go-spiffe/v2 v2.6.0 // indirect
	github.com/streamingfast/logging v0.0.0-20230608130331-f22c91403091 // indirect
	github.com/streamingfast/sf-tracing v0.0.0-20240209202324-9daa52c71a52 // indirect
	github.com/teris-io/shortid v0.0.0-20171029131806-771a37caa5cf // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.43.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.60.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.23.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.23.1 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.23.1 // indirect
	go.opentelemetry.io/otel/exporters/zipkin v1.23.1 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/mock v0.5.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.42.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	google.golang.org/api v0.234.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)

replace github.com/envoyproxy/go-control-plane/envoy => github.com/envoyproxy/go-control-plane/envoy v1.32.4
