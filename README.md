# Local auth proxy

## What is this?

- Forward incoming requests to auth url to verify authentication.
- If authentication is successed, continue passing response's headers to the target url.
- Else, return 401 to the client.

## Usage

- Make sure you have `go` installed.
- Create a `config.yaml` file, here is an example config:

```yaml
addr: :3333

client:
  timeoutMs: 5000 # milliseconds, default 10000

auth:
  url: http://localhost:9000
  allowedRequestHeaders: # Lists the headers (case-insensitive) that are copied from the incoming request to the request made to the external auth service. In addition to the headers listed in this field, the following headers are always included: Origin, Authorization, Cookie, From, Proxy-Authorization, User-Agent, X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto.
    - Origin
    - Authorization
    - workspace
  allowedAuthorizationHeaders: #Lists the headers (case-insensitive) that are copied from the response from the external auth service to the request sent to the upstream backend service (if the external auth service indicates that the request to the upstream backend service should be allowed). In addition to the headers listed in this field, the following headers are always included: Authorization, Location, Proxy-Authenticate, Set-cookie, WWW-Authenticate
    - x-apigateway-userinfo

mappings:
  - forward: http://localhost:3000
    prefix: products # requests to http://localhost:3333/products/api/... will be redirect to http://localhost:3000/api/...
    whitelist:
      - /api/doc*
```

- In the same directory as the config file, run `go run github.com/luuhai48/localauthproxy`
- In your application, update all API URL, from the old `http://localhost:3002/api` to `http://localhost:3333/products/api`
