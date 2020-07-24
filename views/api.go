package views

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/ystv/web-auth/db"
	"github.com/ystv/web-auth/sessions"
)

type JWTClaims struct {
	UserID   int    `json:"userID"`
	Username string `json:"username"`
	jwt.StandardClaims
}

var signingKey = []byte("verygood-secret")

// GetTokenHandler will get a token for the username and password
func GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Write([]byte("Method not allowed"))
		return
	}

	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	password = hashPassword(password)

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid Username or password"))
		return
	}
	if db.ValidUser(username, password) {
		claims := JWTClaims{
			0,
			username,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 5).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Sign the token with our secret
		tokenString, err := token.SignedString(signingKey)
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
	token, err := jwt.ParseWithClaims(myToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})

	if err != nil {
		return false, ""
	}

	claims := token.Claims.(*JWTClaims)
	return token.Valid, claims.Username
}

func SetTokenHandler(w http.ResponseWriter, r *http.Request) {
	expirationTime := time.Now().Add(5 * time.Minute)
	if !sessions.IsLoggedIn(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	claims := &JWTClaims{
		UserID:   sessions.GetUserID(r),
		Username: sessions.GetUsername(r),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing,
	// and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		// If there is an error in creating the JWT
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Finally, we set the client cooke for the "token" as the JWT
	// we generated, also setting the expiry time as the same
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
		Path:    "/",
	})
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
