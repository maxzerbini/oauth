package oauth

import (
	"testing"
)

var _mut *BearerAuthentication

func init() {
	_mut = NewBearerAuthentication(
		"mySecretKey-10101",
		nil)
}

func TestAuthorizationHeader(t *testing.T) {
	code, resp := _sut.generateTokenResponse("password", "user111", "password111", "", "", "", "")
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	t.Logf("Token response: %v", resp)

	header := "Bearer " + resp.(*TokenResponse).Token
	token, err := _mut.checkAuthorizationHeader(header)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Verified token : %v", token)
}

func TestExpiredAuthorizationHeader(t *testing.T) {
	header := `Bearer wMFZSkQ1kSTbQ9mkHufsfeHCnKo05TSEyLyjSiKOafAUQv7s0NClIgBQSDGKoRzeWfB2G0bKO7EE3P9MnaZNxkx2CtWVfTJkCXsIpo2eyF8Nw+ub5nr4Bxmj6JeOumQMrFogBHMnMT7Em7EhqQO+CICQ3cVX5suqsVkEZ/gkXfjKnnEH6qKYz3S3IN/ry3pVGaQc1wAn/cYqPA1SD+CAYqkriWgIGWJmYv3W9eRSoEWgfgigdM6kmZvlDxTlrACLOvzA/JCXK7qnP8TuFz4yAtNmBoNVw0PTjxIdBFJEC7RdZyQcO3SdgGykxgPqGhiW3Z4F7ZG3mzmy/SoSJIPnmmFIreDWt6+QOsUyeHkEu74G`
	_, err := _mut.checkAuthorizationHeader(header)
	if err == nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Error : %v", err)
}
