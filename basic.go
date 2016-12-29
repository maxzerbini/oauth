package oauth

import "gopkg.in/gin-gonic/gin.v1"
import "strings"
import "encoding/base64"
import "errors"

// GetBasicAuthentication get username and password from Authorization header
func GetBasicAuthentication(ctx gin.Context) (username, password string, err error) {
	if header := ctx.Request.Header.Get("Authorization"); header != "" {
		if strings.ToLower(header[:6]) == "basic " {
			// decode header value
			value, err := base64.StdEncoding.DecodeString(header[6:])
			if err != nil {
				return "", "", err
			}
			strValue := string(value)
			if ind := strings.Index(strValue, ":"); ind > 0 {
				return strValue[:ind], strValue[ind+1:], nil
			}
		}
	}
	return "", "", nil
}

// Check Basic Autrhorization header credentials
func CheckBasicAuthentication(username, password string, ctx gin.Context) error {
	u, p, err := GetBasicAuthentication(ctx)
	if err != nil {
		return err
	} else {
		if u != "" && p != "" {
			if u != username && p != password {
				return errors.New("Invalid credentials")
			}
		}
		return nil
	}
}
