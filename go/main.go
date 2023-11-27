package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nakaaaa/linelogin-web/go/line"
)

var lineConfig line.Config

func init() {
	lineConfig.ClientID = os.Getenv("LINE_CHANNEL_ID")
	lineConfig.ClientSecret = os.Getenv("LINE_CHANNEL_SECRET")
}

const callback = "http://localhost:3000/callback"

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.GET("/hello", hello)
	e.GET("/line/auth", webAuthorization)
	e.GET("/line/user", user)

	e.Logger.Fatal(e.Start(":8080"))
}

func hello(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"message": "Hello, World!"})
}

func user(c echo.Context) error {
	t, err := lineConfig.RetiriveLineToken(c.Request().Context(), c.FormValue("code"), callback)
	if err != nil {
		return err
	}
	req, err := lineConfig.VerifyIDToken(c.Request().Context(), t)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{"user_id": req.Sub})
}

func webAuthorization(c echo.Context) error {
	url, err := lineConfig.WebAuthorization(c.Request().Context(), callback)
	if err != nil {
		return err
	}
	fmt.Println(url)

	return c.JSON(http.StatusOK, map[string]string{"url": url})
}
