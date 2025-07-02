package main

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

const (
	DefaultAddr       = ":3333"
	DefaultTimeoutMs  = 10000
	DefaultConfigName = "config"
	DefaultConfigType = "yaml"
)

var DefaultAllowedRequestHeaders = []string{"Origin", "Authorization", "Cookie", "From", "Proxy-Authorization", "User-Agent", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}

var DefaultAllowedAuthorizationHeaders = []string{"Authorization", "Location", "Proxy-Authenticate", "Set-cookie", "WWW-Authenticate"}

type Mapping struct {
	Forward   string
	Prefix    string
	Whitelist []string
}

type Client struct {
	TimeoutMs int
}

type Auth struct {
	Url                         string
	AllowedRequestHeaders       []string
	AllowedAuthorizationHeaders []string
}

type Config struct {
	Addr     string
	Client   Client
	Auth     Auth
	Mappings []Mapping
}

var C Config

func validateValidUrl(path string) bool {
	u, err := url.ParseRequestURI(path)
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

func lowercaseHeaders(headers []string) []string {
	lowercaseHeaders := make([]string, 0)
	for _, h := range headers {
		lowercaseHeaders = append(lowercaseHeaders, strings.ToLower(h))
	}
	return lowercaseHeaders
}

var allowedHeadersCache = make(map[string]bool)

func validateRequestHeaderAllowed(header string, allowedHeaders []string) bool {
	lowercaseHeader := strings.ToLower(header)
	if v, ok := allowedHeadersCache[lowercaseHeader]; ok {
		return v
	}

	headersWithDefault := lowercaseHeaders(append(allowedHeaders, DefaultAllowedRequestHeaders...))
	for _, h := range headersWithDefault {
		if h == lowercaseHeader {
			allowedHeadersCache[lowercaseHeader] = true
			return true
		}
	}
	allowedHeadersCache[lowercaseHeader] = false
	return false
}

var allowedAuthorizationHeadersCache = make(map[string]bool)

func validateAuthorizationHeaderAllowed(header string, allowedHeaders []string) bool {
	lowercaseHeader := strings.ToLower(header)
	if v, ok := allowedAuthorizationHeadersCache[lowercaseHeader]; ok {
		return v
	}

	headersWithDefault := lowercaseHeaders(append(allowedHeaders, DefaultAllowedAuthorizationHeaders...))
	for _, h := range headersWithDefault {
		if h == lowercaseHeader {
			allowedAuthorizationHeadersCache[lowercaseHeader] = true
			return true
		}
	}
	allowedAuthorizationHeadersCache[lowercaseHeader] = false
	return false
}

func main() {
	viper.SetConfigName(DefaultConfigName)
	viper.SetConfigType(DefaultConfigType)
	viper.AddConfigPath(".")

	viper.SetDefault("addr", DefaultAddr)
	viper.SetDefault("client.timeoutMs", DefaultTimeoutMs)

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %s", err.Error())
	}

	if err := viper.Unmarshal(&C); err != nil {
		log.Fatalf("Error parsing config.yaml: %s", err.Error())
	}

	if len(C.Auth.Url) == 0 {
		log.Fatal("Missing \"auth.url\" in config")
	}
	if !validateValidUrl(C.Auth.Url) {
		log.Fatalf("Invalid \"auth.url\" in config: %s", C.Auth.Url)
	}

	if len(C.Mappings) == 0 {
		log.Fatal("No \"mappings\" specified in config")
	}

	for index, m := range C.Mappings {
		if len(m.Forward) == 0 {
			log.Fatalf("Missing \"forward\" in mappings[%d]", index)
		}
		if !validateValidUrl(m.Forward) {
			log.Fatalf("Invalid \"forward\" in mappings[%d]: %s", index, m.Forward)
		}
		if len(m.Prefix) == 0 {
			log.Fatalf("Missing \"prefix\" in mappings[%d]", index)
		}
	}

	type Target struct {
		Url       string
		Whitelist []glob.Glob
	}
	targetMap := make(map[string]Target)
	for _, m := range C.Mappings {
		whiteList := make([]glob.Glob, 0)
		for _, w := range m.Whitelist {
			if g, err := glob.Compile(w); err == nil {
				whiteList = append(whiteList, g)
			}
		}
		targetMap[m.Prefix] = Target{
			Url:       m.Forward,
			Whitelist: whiteList,
		}
	}

	var httpClient = &http.Client{
		Timeout: time.Duration(C.Client.TimeoutMs) * time.Millisecond,
	}

	app := fiber.New(fiber.Config{
		AppName: "Local auth proxy",
	})

	app.Use("*", func(c *fiber.Ctx) error {
		method := c.Method()

		originalUrl := c.OriginalURL()
		prefix := strings.Split(originalUrl, "/")[1]
		target, ok := targetMap[prefix]
		if originalUrl == "/" || !ok {
			return c.Status(http.StatusBadRequest).SendString("Prefix \"" + prefix + "\" not found in mappings")
		}
		path := originalUrl[len(prefix)+1:]

		bypass := false
		for _, w := range target.Whitelist {
			if w.Match(path) {
				bypass = true
				break
			}
		}

		if method == http.MethodOptions {
			if !bypass {
				// forward OPTIONS request to auth url, and return response, headers to client
				req, err := http.NewRequest(http.MethodOptions, C.Auth.Url+path, nil)
				if err != nil {
					return c.Status(http.StatusInternalServerError).SendString(err.Error())
				}

				req.Header = make(http.Header)
				c.Request().Header.VisitAll(func(key, value []byte) {
					header := string(key)
					if validateRequestHeaderAllowed(header, C.Auth.AllowedRequestHeaders) {
						req.Header.Set(header, string(value))
					}
				})
				resp, err := httpClient.Do(req)
				if err != nil {
					return c.Status(http.StatusInternalServerError).SendString(err.Error())
				}

				for k, v := range resp.Header {
					c.Set(k, v[0])
				}
				return c.Status(resp.StatusCode).SendString("")
			}
		}

		var authResp *http.Response
		if !bypass {
			// forward request to auth url, and return headers to next request
			authReq, err := http.NewRequest(method, C.Auth.Url+path, bytes.NewReader([]byte{}))
			if err != nil {
				return c.Status(http.StatusInternalServerError).SendString(err.Error())
			}

			authReq.Header = make(http.Header)
			c.Request().Header.VisitAll(func(key, value []byte) {
				authReq.Header.Set(string(key), string(value))
			})

			authResp, err = httpClient.Do(authReq)
			if err != nil {
				return c.Status(http.StatusInternalServerError).SendString(err.Error())
			}
			// if auth failed, return 401
			if authResp.StatusCode != http.StatusOK {
				for k, v := range authResp.Header {
					c.Set(k, v[0])
				}
				body := make([]byte, authResp.ContentLength)
				authResp.Body.Read(body)
				return c.Status(http.StatusUnauthorized).Send(body)
			}
		}

		// forward request to forward url
		req, err := http.NewRequest(method, target.Url+path, bytes.NewReader(c.Body()))
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString(err.Error())
		}

		req.Header = make(http.Header)
		c.Request().Header.VisitAll(func(key, value []byte) {
			req.Header.Set(string(key), string(value))
		})

		if authResp != nil {
			for k, v := range authResp.Header {
				if validateAuthorizationHeaderAllowed(k, C.Auth.AllowedAuthorizationHeaders) {
					req.Header.Set(k, v[0])
				}
			}
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString(err.Error())
		}

		for k, v := range resp.Header {
			c.Set(k, v[0])
		}
		return c.Status(resp.StatusCode).SendStream(resp.Body)
	})

	if err := app.Listen(C.Addr); err != nil {
		log.Fatal(err)
	}
}
