// path: src/stun/stun.go
package stun

import (
	"encoding/binary"
)

// IsSTUNMessage checks if a UDP payload is a STUN message (RFC 5389)
func IsSTUNMessage(data []byte) bool {
	// STUN header is 20 bytes:
	// 2 (type) + 2 (length) + 4 (magic cookie) + 12 (transaction ID)
	if len(data) < 20 {
		return false
	}

	// Read message type (big endian, network byte order)
	messageType := binary.BigEndian.Uint16(data[0:2])

	// Read message length (big endian)
	// This is the length of the message body, NOT including the 20-byte header
	messageLength := binary.BigEndian.Uint16(data[2:4])

	// Validate that the packet length matches the declared message length
	// Total packet size should be: 20 (header) + messageLength (body)
	if len(data) != int(messageLength)+20 {
		return false
	}

	// RFC 5389 Section 6: The most significant 2 bits of every STUN message MUST be zeros
	// This helps distinguish STUN from other protocols using the same ports
	if (messageType & 0xC000) != 0 {
		return false
	}

	// Filter STUN requests only (not responses or indications)
	// Message Type bits:
	//   Bit 4 (0x0010): 0=request, 1=indication
	//   Bit 8 (0x0100): 0=request/indication, 1=response/error response
	// We want to detect only requests (both bits = 0)
	// This prevents mangling STUN responses which could break WebRTC
	if (messageType & 0x0110) != 0 {
		return false
	}

	// Check magic cookie (RFC 5389 Section 6)
	// Magic cookie is 0x2112A442 (in network byte order)
	// This is a fixed value that helps identify STUN messages
	magicCookie := binary.BigEndian.Uint32(data[4:8])
	if magicCookie != 0x2112A442 {
		return false
	}

	// All checks passed - this is a STUN request
	return true
}

// GetSTUNMessageType returns the STUN message type if it's a valid STUN message
// Returns 0 if not a STUN message
func GetSTUNMessageType(data []byte) uint16 {
	if !IsSTUNMessage(data) {
		return 0
	}
	return binary.BigEndian.Uint16(data[0:2]) & 0x3FFF
}

// Common STUN message types (for debugging/logging)
const (
	BindingRequest            = 0x0001
	BindingResponse           = 0x0101
	BindingErrorResponse      = 0x0111
	SharedSecretRequest       = 0x0002
	SharedSecretResponse      = 0x0102
	SharedSecretErrorResponse = 0x0112
)

// MessageTypeName returns a human-readable name for STUN message types
func MessageTypeName(msgType uint16) string {
	switch msgType {
	case BindingRequest:
		return "Binding Request"
	case BindingResponse:
		return "Binding Response"
	case BindingErrorResponse:
		return "Binding Error Response"
	case SharedSecretRequest:
		return "Shared Secret Request"
	case SharedSecretResponse:
		return "Shared Secret Response"
	case SharedSecretErrorResponse:
		return "Shared Secret Error Response"
	default:
		return "Unknown"
	}
}
