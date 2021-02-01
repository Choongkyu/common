package currentuser

import (
	"context"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
)

type key int

// KeyCurrentUser is a key
const KeyCurrentUser key = iota

// Middleware takes session from context, parses and adds the current user to context
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := verifyToken(r)
		if err != nil {
			if err == http.ErrNoCookie {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), KeyCurrentUser, jwt.MapClaims{})))
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		currentUser, ok := token.Claims.(jwt.MapClaims)
		if !token.Valid || !ok {
			http.Error(w, "Bad jwt", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), KeyCurrentUser, currentUser)))
	})
}

func verifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString, err := r.Cookie("mux")
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_KEY")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil

}
