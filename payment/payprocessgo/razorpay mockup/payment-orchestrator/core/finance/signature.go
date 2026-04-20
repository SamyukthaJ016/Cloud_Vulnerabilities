package finance

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// VerifyWebhookSignature checks the HMAC-SHA256 signature Razorpay sends
// with every webhook. Returns nil if valid, error if tampered or missing.
//
// Razorpay signs the raw request body with your webhook secret.
// Header name: X-Razorpay-Signature
func VerifyWebhookSignature(body []byte, signature string, secret string) error {
	if signature == "" {
		return fmt.Errorf("signature: missing X-Razorpay-Signature header")
	}
	if secret == "" {
		return fmt.Errorf("signature: webhook secret not configured")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	// constant time compare — prevents timing attacks
	if subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) != 1 {
		return fmt.Errorf("signature: mismatch — possible tampered request")
	}

	return nil
}
