package oauth

import (
	"encoding/base64"
	"net/http"
	"testing"

	"gopkg.in/gin-gonic/gin.v1"
)

func TestGetBasicAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)

	req, _ := http.NewRequest("GET", "/token", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password123456")))

	context := gin.Context{Request: req}

	username, password, err := GetBasicAuthentication(context)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	} else {
		if username != "admin" {
			t.Fatalf("Wrong Username = %s", username)
		}
		if password != "password123456" {
			t.Fatalf("Wrong Username = %s", password)
		}
	}
}

func TestVoidBasicAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)

	req, _ := http.NewRequest("GET", "/token", nil)

	context := gin.Context{Request: req}

	username, password, err := GetBasicAuthentication(context)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	} else {
		if username != "" {
			t.Fatalf("Wrong Username = %s", username)
		}
		if password != "" {
			t.Fatalf("Wrong Username = %s", password)
		}
	}

}

func TestCheckBasicAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)

	req, _ := http.NewRequest("GET", "/token", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password123456")))

	context := gin.Context{Request: req}

	err := CheckBasicAuthentication("admin", "password123456", context)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	} else {
		t.Log("Credentials are OK")
	}
}
