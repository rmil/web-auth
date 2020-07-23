package views

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/ystv/web-auth/db"
)

type MyCustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var mySigningKey = []byte("secret")

// GetTokenHandler will get a token for the username and password
func GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Write([]byte("Method not allowed"))
		return
	}

	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid Username or password"))
		return
	}
	if db.ValidUser(username, password) {
		claims := MyCustomClaims{
			username,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 5).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Sign the token with our secret
		tokenString, err := token.SignedString(mySigningKey)
		if err != nil {
			log.Println("Something went wrong with singing token")
			w.Write([]byte("Authentication failed"))
			return
		}
		// Finally, write the token to the browser window
		w.Write([]byte(tokenString))
	} else {
		w.Write([]byte("Authentication failed"))
	}
}

// ValidateToken will validate the token
func ValidateToken(myToken string) (bool, string) {
	token, err := jwt.ParseWithClaims(myToken, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(mySigningKey), nil
	})

	if err != nil {
		return false, ""
	}

	claims := token.Claims.(*MyCustomClaims)
	return token.Valid, claims.Username
}

func TestAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		var err error
		var message string
		var status Status
		if r.Header["Token"] == nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		token := r.Header["Token"][0]

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")

		IsTokenValid, username := ValidateToken(token)
		// When the token is not valid show
		// the default error JOSN document
		if !IsTokenValid {
			status = Status{
				StatusCode: http.StatusInternalServerError,
				Message:    message,
			}
			w.WriteHeader(http.StatusInternalServerError)
			// the following statmeent will write the
			// JSON document to the HTTP ReponseWriter object
			err = json.NewEncoder(w).Encode(status)
			if err != nil {
				panic(err)
			}
			return
		}

		log.Printf("token is valid \"%s\" is logged in", username)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)

		status = Status{
			StatusCode: http.StatusOK,
			Message:    "Good",
		}

		err = json.NewEncoder(w).Encode(status)
		if err != nil {
			panic(err)
		}
	}
}

type Status struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}
