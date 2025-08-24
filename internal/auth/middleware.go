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
			log.Println("RequireRoles: No token found in context")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		claims, ok := token.(*jwt.Token).Claims.(jwt.MapClaims)
		if !ok {
			log.Println("RequireRoles: Claims type assertion failed")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		userRole, ok := claims["role"].(string)
		if !ok {
			log.Println("RequireRoles: Role not found in claims", claims)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("RequireRoles: User role from token: %s\n", userRole)
		for _, role := range roles {
			if userRole == role {
				next(w, r)
				return
			}
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}
