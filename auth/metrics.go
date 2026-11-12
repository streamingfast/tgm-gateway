package auth

import "github.com/streamingfast/dmetrics"

var MetricSet = dmetrics.NewSet()
var ReissueCounter = MetricSet.NewCounter("auth_payment_gateway_reissue_counter", "How many times the 'reissue' method was called to get an updated JWT")
var AuthCounter = MetricSet.NewCounterVec("auth_payment_gateway_auth_counter", []string{"method", "jwt_lifetime_bucket"}, "How many requests were authenticated, by auth method and JWT lifetime bucket ('none' for API key)")
