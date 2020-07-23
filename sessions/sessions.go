package sessions

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

// Store the cookie store which is going to store session data in the cookie
var Store = sessions.NewCookieStore([]byte("secret-password"))

// IsLoggedIn will check if the user has an active session and return True
func IsLoggedIn(r *http.Request) bool {
	session, _ := Store.Get(r, "session")
	if session.Values["loggedin"] == "true" {
		return true
	}
	return false
}

func GetUsername(r *http.Request) string {
	session, _ := Store.Get(r, "session")
	return fmt.Sprintf("%v", session.Values["username"])
}
