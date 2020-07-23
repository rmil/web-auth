package main

import (
	"log"
	"net/http"

	"github.com/ystv/web-auth/views"
)

func main() {
	views.PopulateTemplates()

	// Login logout
	http.HandleFunc("/login/", views.LoginFunc)
	http.HandleFunc("/logout/", views.LogoutFunc)
	http.HandleFunc("/signup/", views.SignUpFunc)

	// Login required
	http.HandleFunc("/internal/", views.RequiresLogin(views.InternalFunc))

	// public
	http.HandleFunc("/", views.WelcomeFunc)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
