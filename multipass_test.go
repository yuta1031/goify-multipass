package multipass_test

import (
	"fmt"
	"testing"

	multipass "github.com/yuta1031/goify-multipass"
)

const secret = "e2c1dc490fd04ad8bbcc426316196dba"

var customerInfo = map[string]interface{}{
	"email": "xmhscratch@gmail.com",
}

func TestTokenGenerate(t *testing.T) {
	m, err := multipass.New(secret)
	if err != nil {
		t.Errorf("failed: %v", err)
		return
	}

	token, err := m.Encode(customerInfo)
	if err != nil {
		t.Errorf("token generate failed: %v", err)
		return
	}
	fmt.Println(token)
}

func TestURLGenerate(t *testing.T) {
	m, err := multipass.New(secret)
	if err != nil {
		t.Errorf("failed: %v", err)
		return
	}

	urlString, err := m.GenerateURL(customerInfo, "yourstorename.myshopify.com")
	if err != nil {
		t.Errorf("url generate failed: %v", err)
		return
	}
	fmt.Println(urlString)
}
