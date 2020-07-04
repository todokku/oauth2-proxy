package middleware

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

const jwtRegexFormat = `^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+$`

func NewJwtSessionLoader(sessionLoaders []middlewareapi.TokenToSessionLoader) alice.Constructor {
	js := &jwtSession{
		jwtRegex:       regexp.MustCompile(jwtRegexFormat),
		sessionLoaders: sessionLoaders,
	}
	return js.loadSession
}

type jwtSession struct {
	jwtRegex       *regexp.Regexp
	sessionLoaders []middlewareapi.TokenToSessionLoader
}

func (j *jwtSession) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := GetRequestScope(req)
		if scope != nil {
			// RequestScope should have been injected before this middleware
			// If this happens it's a programming error
			panic("RequestScope not found")
		}

		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
		}

		session, err := j.getJwtSession(req)
		if err != nil {
			logger.Printf("Error retrieving session from token in Authorization header: %v", err)
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getJwtSession loads a session based on a JWT token in the authorization header.
// (see the config options skip-jwt-bearer-tokens and extra-jwt-issuers)
func (j *jwtSession) getJwtSession(req *http.Request) (*sessionsapi.SessionState, error) {
	rawBearerToken, err := j.findBearerToken(req)
	if err != nil {
		return nil, err
	}
	if rawBearerToken == "" {
		// No bearer token was provided in the request, don't attempt to load a sesssion
		return nil, nil
	}

	for _, loader := range j.sessionLoaders {
		bearerToken, err := loader.Verifier.Verify(req.Context(), rawBearerToken)
		if err == nil {
			// The token was verified, convert it to a session
			return loader.TokenToSession(req.Context(), rawBearerToken, bearerToken)
		}
	}

	return nil, fmt.Errorf("unable to verify jwt token %s", req.Header.Get("Authorization"))
}

// findBearerToken finds a valid JWT token from the Authorization header of a given request.
func (j *jwtSession) findBearerToken(req *http.Request) (string, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		// No auth header, don't attempt to load a session
		return "", nil
	}

	s := strings.SplitN(auth, " ", 2)
	if len(s) != 2 {
		return "", fmt.Errorf("invalid authorization header %s", auth)
	}

	var rawBearerToken string
	if s[0] == "Bearer" && j.jwtRegex.MatchString(s[1]) {
		rawBearerToken = s[1]
	} else if s[0] == "Basic" {
		// Check if we have a Bearer token masquerading in Basic
		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			return "", err
		}
		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			return "", fmt.Errorf("invalid format %s", b)
		}
		user, password := pair[0], pair[1]

		// check user, user+password, or just password for a token
		if j.jwtRegex.MatchString(user) {
			// Support blank passwords or magic `x-oauth-basic` passwords - nothing else
			if password == "" || password == "x-oauth-basic" {
				rawBearerToken = user
			}
		} else if j.jwtRegex.MatchString(password) {
			// support passwords and ignore user
			rawBearerToken = password
		}
	}
	if rawBearerToken == "" {
		return "", fmt.Errorf("no valid bearer token found in authorization header")
	}

	return rawBearerToken, nil
}
