package main

import (
	"github.com/maxzerbini/oauth"
	cors "gopkg.in/gin-contrib/cors.v1"
	"gopkg.in/gin-gonic/gin.v1"
)

/*
   Resource Server Example

	Get Customers

		GET http://localhost:3200/customers
		User-Agent: Fiddler
		Host: localhost:3200
		Content-Length: 0
		Content-Type: application/json
		Authorization: Bearer {access_token}

	Get Orders

		GET http://localhost:3200/customers/12345/orders
		User-Agent: Fiddler
		Host: localhost:3200
		Content-Length: 0
		Content-Type: application/json
		Authorization: Bearer {access_token}

	{access_token} is produced by the Authorization Server response (see example /test/authserver).

*/
func main() {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(cors.Default()) // enable Cross-Origin Resource Sharing
	gin.SetMode(gin.DebugMode)
	registerAPI(router)
	router.Run(":3200")
}

func registerAPI(router *gin.Engine) {

	authorized := router.Group("/")
	// use the Bearer Athentication middleware
	authorized.Use(oauth.Authorize("mySecretKey-10101", nil))

	authorized.GET("/customers", GetCustomers)
	authorized.GET("/customers/:id/orders", GetOrders)
}

func GetCustomers(c *gin.Context) {

	c.JSON(200, gin.H{
		"Status":        "verified",
		"Customer":      "test001",
		"CustomerName":  "Max",
		"CustomerEmail": "test@test.com",
	})
}

func GetOrders(c *gin.Context) {

	c.JSON(200, gin.H{
		"status":          "sent",
		"customer":        c.Param("id"),
		"OrderId":         "100234",
		"TotalOrderItems": "199",
	})
}
