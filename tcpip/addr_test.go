package tcpip

import (
	"testing"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantV   uint8
		wantErr string
	}{
		{"Short buffer", nil, 0, ErrShortBuffer.Error()},
		{"Valid IPv4", []byte{0x40}, 4, ""},
		{"Valid IPv6", []byte{0x60}, 6, ""},
		{"Invalid Version", []byte{0x50}, 5, "invalid ip header version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotV, err := Version(tt.b)
			if gotV != tt.wantV {
				t.Errorf("Version() gotV = %v, want %v", gotV, tt.wantV)
			}
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("Version() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("Version() unexpected error: %v", err)
			}
		})
	}
}

func TestIPv4TotalLen(t *testing.T) {
	validIPv4 := make([]byte, 20) // MinIPv4HdrLen is presumably 20
	validIPv4[0] = 0x45           // Version 4, IHL 5 (5 * 4 = 20 bytes)
	validIPv4[2] = 0
	validIPv4[3] = 20 // Total length = 20

	invalidIHL := make([]byte, 20)
	invalidIHL[0] = 0x44 // IHL 4 (4 * 4 = 16 bytes) which is < MinIPv4HdrLen
	invalidIHL[2] = 0
	invalidIHL[3] = 20

	invalidPktLen := make([]byte, 20)
	invalidPktLen[0] = 0x45 // IHL 5
	invalidPktLen[2] = 0
	invalidPktLen[3] = 10 // Total length 10, which is < IHL 20

	shortBufAfterLen := make([]byte, 20)
	shortBufAfterLen[0] = 0x45
	shortBufAfterLen[2] = 0
	shortBufAfterLen[3] = 30 // Total length 30, but actual buffer length is 20

	tests := []struct {
		name    string
		b       []byte
		wantLen int
		wantErr string
	}{
		{"Short buffer initially", make([]byte, 10), 0, ErrShortBuffer.Error()},
		{"Invalid header length", invalidIHL, 0, "invalid ipv4 header length"},
		{"Invalid packet length", invalidPktLen, 0, "invalid ipv4 packet length"},
		{"Short buffer after length parsed", shortBufAfterLen, 0, ErrShortBuffer.Error()},
		{"Valid IPv4", validIPv4, 20, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLen, err := IPv4TotalLen(tt.b)
			if gotLen != tt.wantLen {
				t.Errorf("IPv4TotalLen() gotLen = %v, want %v", gotLen, tt.wantLen)
			}
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("IPv4TotalLen() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("IPv4TotalLen() unexpected error: %v", err)
			}
		})
	}
}

func TestIPv6TotalLen(t *testing.T) {
	validIPv6 := make([]byte, 50)
	validIPv6[0] = 0x60 // IPv6
	validIPv6[4] = 0    // Payload length byte 1
	validIPv6[5] = 10   // Payload length byte 2 -> total length is FixIPv6HdrLen (40) + 10 = 50

	shortBufAfterLen := make([]byte, 45)
	shortBufAfterLen[0] = 0x60
	shortBufAfterLen[4] = 0
	shortBufAfterLen[5] = 10 // Tells us we need 50 bytes, but the buffer is only 45 bytes long

	tests := []struct {
		name    string
		b       []byte
		wantLen int
		wantErr string
	}{
		{"Short buffer initially", make([]byte, 30), 0, ErrShortBuffer.Error()},
		{"Short buffer after length parsed", shortBufAfterLen, 0, ErrShortBuffer.Error()},
		{"Valid IPv6", validIPv6, 50, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLen, err := IPv6TotalLen(tt.b)
			if gotLen != tt.wantLen {
				t.Errorf("IPv6TotalLen() gotLen = %v, want %v", gotLen, tt.wantLen)
			}
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("IPv6TotalLen() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("IPv6TotalLen() unexpected error: %v", err)
			}
		})
	}
}

func TestTotalLen(t *testing.T) {
	validIPv4 := make([]byte, 20)
	validIPv4[0] = 0x45
	validIPv4[2] = 0
	validIPv4[3] = 20

	validIPv6 := make([]byte, 50)
	validIPv6[0] = 0x60
	validIPv6[4] = 0
	validIPv6[5] = 10

	tests := []struct {
		name    string
		b       []byte
		wantLen int
		wantErr string
	}{
		{"Version Error", nil, 0, ErrShortBuffer.Error()},
		{"IPv4 Path Route", validIPv4, 20, ""},
		{"IPv6 Path Route", validIPv6, 50, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLen, err := TotalLen(tt.b)
			if gotLen != tt.wantLen {
				t.Errorf("TotalLen() gotLen = %v, want %v", gotLen, tt.wantLen)
			}
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("TotalLen() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("TotalLen() unexpected error: %v", err)
			}
		})
	}
}
