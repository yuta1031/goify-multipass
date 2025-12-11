package multipass

import "time"

// TimeISO8601Layout timestamp in ISO8601 encoding
const TimeISO8601Layout = "2013-04-11T15:16:23-04:00"

// // CustomerInfo comment
// type CustomerInfo struct {
// 	Email     string `json:"email"`
// 	CreatedAt string `json:"created_at"`
// 	RemoteIP  string `json:"remote_ip"`
// 	ReturnTo  string `json:"return_to"`
// }

// Multipass comment
type Multipass struct {
	EncryptionKey []byte
	SignatureKey  []byte
	Location      *time.Location
}
