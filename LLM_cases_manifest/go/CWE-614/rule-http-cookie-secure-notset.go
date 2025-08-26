package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
)

// True Positives (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "sessionToken",
		Value:    "abc123",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   3600,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-http-cookie-secure-notset
	cookie := &http.Cookie{
		Name:     "userID",
		Value:    "user123",
		Path:     "/dashboard",
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "authToken",
		Value:    "token123",
		Path:     "/",
		Domain:   "example.com",
		HttpOnly: true,
		MaxAge:   86400,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-http-cookie-secure-notset
	cookie := &http.Cookie{
		Name:  "preferences",
		Value: "theme=dark",
		Path:  "/",
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_5() {
	e := echo.New()
	e.GET("/set-cookie", func(c echo.Context) error {
		// ruleid: rule-http-cookie-secure-notset
		cookie := new(http.Cookie)
		cookie.Name = "session"
		cookie.Value = "session-value"
		cookie.HttpOnly = true
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Cookie set")
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "rememberMe",
		Value:    "true",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   2592000, // 30 days
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_7() {
	e := echo.New()
	e.GET("/login", func(c echo.Context) error {
		// ruleid: rule-http-cookie-secure-notset
		cookie := &http.Cookie{
			Name:     "authToken",
			Value:    "token456",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   3600,
		}
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Logged in")
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Create explicit cookie with Secure set to false
	// ruleid: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "sessionID",
		Value:    "sid123",
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Explicitly set to false
		MaxAge:   3600,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_9() {
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	
	http.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Values["user"] = "john"
		// ruleid: rule-http-cookie-secure-notset
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
		}
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	isSecure := false
	// ruleid: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "apiToken",
		Value:    "api123",
		Path:     "/api",
		HttpOnly: true,
		Secure:   isSecure,
		MaxAge:   3600,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-http-cookie-secure-notset
	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{
		Name:     "longLivedToken",
		Value:    "forever123",
		Expires:  expiration,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_12() {
	e := echo.New()
	e.GET("/admin", func(c echo.Context) error {
		// ruleid: rule-http-cookie-secure-notset
		cookie := &http.Cookie{
			Name:     "adminSession",
			Value:    "admin123",
			Path:     "/admin",
			Domain:   "example.com",
			HttpOnly: true,
			MaxAge:   1800,
		}
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Admin area")
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Dynamic cookie creation with missing Secure attribute
	cookieName := "dynamicCookie"
	cookieValue := "dynamic123"
	
	// ruleid: rule-http-cookie-secure-notset
	cookie := &http.Cookie{
		Name:  cookieName,
		Value: cookieValue,
		Path:  "/",
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-http-cookie-secure-notset
	http.SetCookie(w, &http.Cookie{
		Name:     "directCookie",
		Value:    "direct123",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   3600,
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	for _, user := range []string{"admin", "user", "guest"} {
		// ruleid: rule-http-cookie-secure-notset
		cookie := http.Cookie{
			Name:     fmt.Sprintf("%sRole", user),
			Value:    user,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   3600,
		}
		http.SetCookie(w, &cookie)
	}
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// ok: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "sessionToken",
		Value:    "abc123",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   3600,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// ok: rule-http-cookie-secure-notset
	cookie := &http.Cookie{
		Name:     "userID",
		Value:    "user123",
		Path:     "/dashboard",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// ok: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "authToken",
		Value:    "token123",
		Path:     "/",
		Domain:   "example.com",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   86400,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// ok: rule-http-cookie-secure-notset
	cookie := &http.Cookie{
		Name:   "preferences",
		Value:  "theme=dark",
		Path:   "/",
		Secure: true,
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_5() {
	e := echo.New()
	e.GET("/set-cookie", func(c echo.Context) error {
		// ok: rule-http-cookie-secure-notset
		cookie := new(http.Cookie)
		cookie.Name = "session"
		cookie.Value = "session-value"
		cookie.HttpOnly = true
		cookie.Secure = true
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Cookie set")
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// ok: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "rememberMe",
		Value:    "true",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   2592000, // 30 days
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_7() {
	e := echo.New()
	e.GET("/login", func(c echo.Context) error {
		// ok: rule-http-cookie-secure-notset
		cookie := &http.Cookie{
			Name:     "authToken",
			Value:    "token456",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   3600,
		}
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Logged in")
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	isProduction := true
	// ok: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "sessionID",
		Value:    "sid123",
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction,
		MaxAge:   3600,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_9() {
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	
	http.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Values["user"] = "john"
		// ok: rule-http-cookie-secure-notset
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
			Secure:   true,
		}
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Reading secure setting from environment
	secureStr := os.Getenv("COOKIE_SECURE")
	isSecure := secureStr != "false"
	
	// ok: rule-http-cookie-secure-notset
	cookie := http.Cookie{
		Name:     "apiToken",
		Value:    "api123",
		Path:     "/api",
		HttpOnly: true,
		Secure:   isSecure,
		MaxAge:   3600,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// ok: rule-http-cookie-secure-notset
	expiration := time.Now().Add(365 * 24 * time.Hour)
	cookie := http.Cookie{
		Name:     "longLivedToken",
		Value:    "forever123",
		Expires:  expiration,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_12() {
	e := echo.New()
	e.GET("/admin", func(c echo.Context) error {
		// ok: rule-http-cookie-secure-notset
		cookie := &http.Cookie{
			Name:     "adminSession",
			Value:    "admin123",
			Path:     "/admin",
			Domain:   "example.com",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   1800,
		}
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Admin area")
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Dynamic cookie creation with Secure attribute
	cookieName := "dynamicCookie"
	cookieValue := "dynamic123"
	
	// ok: rule-http-cookie-secure-notset
	cookie := &http.Cookie{
		Name:   cookieName,
		Value:  cookieValue,
		Path:   "/",
		Secure: true,
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// ok: rule-http-cookie-secure-notset
	http.SetCookie(w, &http.Cookie{
		Name:     "directCookie",
		Value:    "direct123",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   3600,
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	for _, user := range []string{"admin", "user", "guest"} {
		// ok: rule-http-cookie-secure-notset
		cookie := http.Cookie{
			Name:     fmt.Sprintf("%sRole", user),
			Value:    user,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   3600,
		}
		http.SetCookie(w, &cookie)
	}
}
// {/fact}

func main() {
	// This is just a placeholder main function
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	http.ListenAndServe(":8080", nil)
}