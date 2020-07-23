package views

import (
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/ystv/web-auth/sessions"
)

var (
	welcomeTemplate  *template.Template
	loginTemplate    *template.Template
	signupTemplate   *template.Template
	internalTemplate *template.Template
)

func PopulateTemplates() {
	var allFiles []string
	templatesDir := "./public/templates/"
	files, err := ioutil.ReadDir(templatesDir)
	if err != nil {
		log.Println("Error reading template dir")
	}
	for _, file := range files {
		filename := file.Name()
		if strings.HasSuffix(filename, ".tmpl") {
			allFiles = append(allFiles, templatesDir+filename)
		}
	}
	if err != nil {
		log.Fatalln(err)
	}
	templates := template.Must(template.ParseFiles(allFiles...))

	welcomeTemplate = templates.Lookup("welcome.tmpl")
	loginTemplate = templates.Lookup("login.tmpl")
	signupTemplate = templates.Lookup("signup.tmpl")
	internalTemplate = templates.Lookup("internal.tmpl")
}

func WelcomeFunc(w http.ResponseWriter, r *http.Request) {
	context := getData(r)
	if r.Method == "GET" {
		welcomeTemplate.Execute(w, context)
	}
}

type Context struct {
	Greeting string
	Version  string
	User     User
	Methods  []Method
}

type User struct {
	IsLoggedIn bool
	Username   string
}

type Method struct {
	Name     string
	Location string
}

func getData(r *http.Request) *Context {
	c := Context{Version: "0.0.1",
		Greeting: "Auth service",
		User: User{
			IsLoggedIn: sessions.IsLoggedIn(r),
			Username:   sessions.GetUsername(r),
		},
		Methods: []Method{
			{
				Name:     "Internal",
				Location: "login",
			},
			{
				Name:     "Github",
				Location: "/auth/github",
			},
		},
	}
	return &c
}