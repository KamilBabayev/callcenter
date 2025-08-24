package auth

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var JwtKey = []byte("your_secret_key")

func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("JWTMiddleware: %s %s", r.Method, r.URL.Path)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return JwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Pass token to context
		ctx := context.WithValue(r.Context(), "userToken", token)
		next(w, r.WithContext(ctx))
	}
}

func RequireRoles(roles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value("userToken")
		if token == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		claims, ok := token.(*jwt.Token).Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		userRole, ok := claims["role"].(string)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if userRole == "admin" {
			next(w, r)
			return
		}
		for _, role := range roles {
			if userRole == role {
				next(w, r)
				return
			}
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

func RequireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value("userToken")
		if token == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		claims, ok := token.(*jwt.Token).Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		userRole, ok := claims["role"].(string)
		if !ok || (userRole != role && userRole != "admin") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
