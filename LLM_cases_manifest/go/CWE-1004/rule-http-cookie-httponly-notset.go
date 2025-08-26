package main

import (
	"fmt"
	"net/http"
	"time"
	"os"
	"crypto/rand"
	"encoding/base64"
	"github.com/gorilla/sessions"
	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Creating a cookie without HttpOnly flag
	cookie := http.Cookie{
		Name:     "sessionToken",
		Value:    "abc123",
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
		// ruleid: rule-http-cookie-httponly-notset
		HttpOnly: false, // Explicitly set to false
	}
	http.SetCookie(w, &cookie)
	fmt.Fprintf(w, "Cookie has been set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Creating a cookie without specifying HttpOnly flag (defaults to false)
	cookie := http.Cookie{
		Name:    "userID",
		Value:   "user12345",
		Path:    "/",
		Expires: time.Now().Add(30 * 24 * time.Hour),
		Secure:  true,
		// HttpOnly is not set, defaults to false
	}
	// ruleid: rule-http-cookie-httponly-notset
	http.SetCookie(w, &cookie)
	fmt.Fprintf(w, "User cookie has been set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Creating a session cookie without HttpOnly
	expiration := time.Now().Add(365 * 24 * time.Hour)
	// ruleid: rule-http-cookie-httponly-notset
	http.SetCookie(w, &http.Cookie{
		Name:    "authToken",
		Value:   "t9876xyz",
		Expires: expiration,
	})
	fmt.Fprintf(w, "Authentication cookie set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_4() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Setting multiple cookies, none with HttpOnly
		// ruleid: rule-http-cookie-httponly-notset
		http.SetCookie(w, &http.Cookie{
			Name:   "preference",
			Value:  "darkmode",
			MaxAge: 86400 * 30,
		})
		
		// ruleid: rule-http-cookie-httponly-notset
		http.SetCookie(w, &http.Cookie{
			Name:   "language",
			Value:  "en-US",
			MaxAge: 86400 * 30,
		})
		
		fmt.Fprintf(w, "Preferences saved")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Creating a cookie with explicit SameSite policy but no HttpOnly
	cookie := &http.Cookie{
		Name:     "cart",
		Value:    "item1,item2,item3",
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	}
	// ruleid: rule-http-cookie-httponly-notset
	http.SetCookie(w, cookie)
	fmt.Fprintf(w, "Shopping cart cookie set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_6() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Login handler setting auth cookie without HttpOnly
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")
			
			if isValidUser(username, password) {
				sessionID := generateSessionID()
				// ruleid: rule-http-cookie-httponly-notset
				http.SetCookie(w, &http.Cookie{
					Name:    "session",
					Value:   sessionID,
					Expires: time.Now().Add(1 * time.Hour),
					Secure:  true,
				})
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			}
		}
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Setting a temporary cookie for tracking without HttpOnly
	trackingID := generateTrackingID()
	// ruleid: rule-http-cookie-httponly-notset
	cookie := &http.Cookie{
		Name:   "tracker",
		Value:  trackingID,
		MaxAge: 3600,
		Path:   "/",
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_8() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Using Gin framework to set cookie without HttpOnly
		// ruleid: rule-http-cookie-httponly-notset
		c.SetCookie(
			"user_session",
			"abc123xyz",
			3600,
			"/",
			"example.com",
			true,  // Secure
			false, // HttpOnly explicitly set to false
		)
		c.String(http.StatusOK, "Session cookie set")
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_9(e *echo.Echo) {
	e.GET("/set-cookie", func(c echo.Context) error {
		// Using Echo framework to set cookie without HttpOnly
		cookie := new(http.Cookie)
		cookie.Name = "session_id"
		cookie.Value = "random_session_value"
		cookie.Expires = time.Now().Add(24 * time.Hour)
		// ruleid: rule-http-cookie-httponly-notset
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Cookie set")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_10() {
	// Using gorilla/sessions without HttpOnly
	var store = sessions.NewCookieStore([]byte("something-very-secret"))
	
	http.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Values["user"] = "john"
		
		// Configure the session cookie
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			Secure:   true,
			// ruleid: rule-http-cookie-httponly-notset
			HttpOnly: false, // Explicitly set to false
		}
		
		session.Save(r, w)
		fmt.Fprintln(w, "Session saved")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Setting a cookie with dynamic value but no HttpOnly
	userID := r.URL.Query().Get("id")
	if userID != "" {
		// ruleid: rule-http-cookie-httponly-notset
		http.SetCookie(w, &http.Cookie{
			Name:   "last_visited_user",
			Value:  userID,
			MaxAge: 300, // 5 minutes
		})
	}
	fmt.Fprintf(w, "User visit recorded")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_12() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Setting a cookie with conditional logic but no HttpOnly
		theme := r.FormValue("theme")
		if theme == "" {
			theme = "light"
		}
		
		// ruleid: rule-http-cookie-httponly-notset
		cookie := &http.Cookie{
			Name:   "theme_preference",
			Value:  theme,
			MaxAge: 30 * 24 * 60 * 60, // 30 days
		}
		http.SetCookie(w, cookie)
		
		fmt.Fprintf(w, "Theme preference saved")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Setting a cookie with base64 encoded value but no HttpOnly
	data := []byte("sensitive-user-data")
	encoded := base64.StdEncoding.EncodeToString(data)
	
	// ruleid: rule-http-cookie-httponly-notset
	http.SetCookie(w, &http.Cookie{
		Name:    "user_data",
		Value:   encoded,
		Expires: time.Now().Add(24 * time.Hour),
		Secure:  true,
	})
	
	fmt.Fprintf(w, "User data saved")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_14() {
	http.HandleFunc("/remember-me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if r.FormValue("remember") == "yes" {
				// Setting a long-lived cookie without HttpOnly
				token := generateRememberMeToken()
				// ruleid: rule-http-cookie-httponly-notset
				http.SetCookie(w, &http.Cookie{
					Name:    "remember_token",
					Value:   token,
					Expires: time.Now().Add(30 * 24 * time.Hour),
					Path:    "/",
				})
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Setting a cookie with SameSite None but no HttpOnly
	// ruleid: rule-http-cookie-httponly-notset
	http.SetCookie(w, &http.Cookie{
		Name:     "cross_site_cookie",
		Value:    "some_value",
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Secure:   true, // Required for SameSite=None
	})
	fmt.Fprintf(w, "Cross-site cookie set")
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Creating a cookie with HttpOnly flag set to true
	cookie := http.Cookie{
		Name:     "sessionToken",
		Value:    "abc123",
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
		// ok: rule-http-cookie-httponly-notset
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	fmt.Fprintf(w, "Secure cookie has been set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Creating a session cookie with HttpOnly flag
	expiration := time.Now().Add(365 * 24 * time.Hour)
	// ok: rule-http-cookie-httponly-notset
	http.SetCookie(w, &http.Cookie{
		Name:     "authToken",
		Value:    "t9876xyz",
		Expires:  expiration,
		HttpOnly: true,
		Secure:   true,
	})
	fmt.Fprintf(w, "Secure authentication cookie set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_3() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Setting multiple cookies, all with HttpOnly
		// ok: rule-http-cookie-httponly-notset
		http.SetCookie(w, &http.Cookie{
			Name:     "preference",
			Value:    "darkmode",
			MaxAge:   86400 * 30,
			HttpOnly: true,
		})
		
		// ok: rule-http-cookie-httponly-notset
		http.SetCookie(w, &http.Cookie{
			Name:     "language",
			Value:    "en-US",
			MaxAge:   86400 * 30,
			HttpOnly: true,
		})
		
		fmt.Fprintf(w, "Secure preferences saved")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Creating a cookie with explicit SameSite policy and HttpOnly
	cookie := &http.Cookie{
		Name:     "cart",
		Value:    "item1,item2,item3",
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		// ok: rule-http-cookie-httponly-notset
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	fmt.Fprintf(w, "Secure shopping cart cookie set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_5() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Login handler setting auth cookie with HttpOnly
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")
			
			if isValidUser(username, password) {
				sessionID := generateSessionID()
				// ok: rule-http-cookie-httponly-notset
				http.SetCookie(w, &http.Cookie{
					Name:     "session",
					Value:    sessionID,
					Expires:  time.Now().Add(1 * time.Hour),
					Secure:   true,
					HttpOnly: true,
				})
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			}
		}
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Setting a temporary cookie for tracking with HttpOnly
	trackingID := generateTrackingID()
	// ok: rule-http-cookie-httponly-notset
	cookie := &http.Cookie{
		Name:     "tracker",
		Value:    trackingID,
		MaxAge:   3600,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_7() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Using Gin framework to set cookie with HttpOnly
		// ok: rule-http-cookie-httponly-notset
		c.SetCookie(
			"user_session",
			"abc123xyz",
			3600,
			"/",
			"example.com",
			true, // Secure
			true, // HttpOnly set to true
		)
		c.String(http.StatusOK, "Secure session cookie set")
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_8(e *echo.Echo) {
	e.GET("/set-cookie", func(c echo.Context) error {
		// Using Echo framework to set cookie with HttpOnly
		cookie := new(http.Cookie)
		cookie.Name = "session_id"
		cookie.Value = "random_session_value"
		cookie.Expires = time.Now().Add(24 * time.Hour)
		// ok: rule-http-cookie-httponly-notset
		cookie.HttpOnly = true
		cookie.Secure = true
		c.SetCookie(cookie)
		return c.String(http.StatusOK, "Secure cookie set")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_9() {
	// Using gorilla/sessions with HttpOnly
	var store = sessions.NewCookieStore([]byte("something-very-secret"))
	
	http.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Values["user"] = "john"
		
		// Configure the session cookie
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			Secure:   true,
			// ok: rule-http-cookie-httponly-notset
			HttpOnly: true,
		}
		
		session.Save(r, w)
		fmt.Fprintln(w, "Secure session saved")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Setting a cookie with dynamic value and HttpOnly
	userID := r.URL.Query().Get("id")
	if userID != "" {
		// ok: rule-http-cookie-httponly-notset
		http.SetCookie(w, &http.Cookie{
			Name:     "last_visited_user",
			Value:    userID,
			MaxAge:   300, // 5 minutes
			HttpOnly: true,
		})
	}
	fmt.Fprintf(w, "User visit securely recorded")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_11() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Setting a cookie with conditional logic and HttpOnly
		theme := r.FormValue("theme")
		if theme == "" {
			theme = "light"
		}
		
		// ok: rule-http-cookie-httponly-notset
		cookie := &http.Cookie{
			Name:     "theme_preference",
			Value:    theme,
			MaxAge:   30 * 24 * 60 * 60, // 30 days
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		
		fmt.Fprintf(w, "Theme preference securely saved")
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Setting a cookie with base64 encoded value and HttpOnly
	data := []byte("sensitive-user-data")
	encoded := base64.StdEncoding.EncodeToString(data)
	
	// ok: rule-http-cookie-httponly-notset
	http.SetCookie(w, &http.Cookie{
		Name:     "user_data",
		Value:    encoded,
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
		HttpOnly: true,
	})
	
	fmt.Fprintf(w, "User data securely saved")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_13() {
	http.HandleFunc("/remember-me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if r.FormValue("remember") == "yes" {
				// Setting a long-lived cookie with HttpOnly
				token := generateRememberMeToken()
				// ok: rule-http-cookie-httponly-notset
				http.SetCookie(w, &http.Cookie{
					Name:     "remember_token",
					Value:    token,
					Expires:  time.Now().Add(30 * 24 * time.Hour),
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
				})
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Setting a cookie with SameSite None and HttpOnly
	// ok: rule-http-cookie-httponly-notset
	http.SetCookie(w, &http.Cookie{
		Name:     "cross_site_cookie",
		Value:    "some_value",
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Secure:   true, // Required for SameSite=None
		HttpOnly: true,
	})
	fmt.Fprintf(w, "Secure cross-site cookie set")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Using default cookie store with HttpOnly explicitly set
	cookieValue := generateRandomString(32)
	// ok: rule-http-cookie-httponly-notset
	cookie := &http.Cookie{
		Name:     "api_session",
		Value:    cookieValue,
		Path:     "/api",
		Domain:   "api.example.com",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
// {/fact}

// Helper functions

func isValidUser(username, password string) bool {
	// In a real application, this would validate against a database
	return username == "admin" && password == "secure_password"
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func generateTrackingID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generateRememberMeToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:length]
}

func main() {
	// This is just a placeholder main function
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	http.ListenAndServe(":8080", nil)
}