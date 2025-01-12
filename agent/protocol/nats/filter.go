package nats

import (
	"kyanos/agent/protocol"
	"kyanos/bpf"
)

var _ protocol.ProtocolFilter = NATSFilter{}

type NATSFilter struct {
}

func (filter NATSFilter) FilterByProtocol(protocol bpf.AgentTrafficProtocolT) bool {
	return protocol == bpf.AgentTrafficProtocolTKProtocolNATS
}

func (filter NATSFilter) FilterByRequest() bool {
	return false
}

func (filter NATSFilter) FilterByResponse() bool {
	return false
}

func (filter NATSFilter) Filter(parsedReq protocol.ParsedMessage, parsedResp protocol.ParsedMessage) bool {
	return true
}
