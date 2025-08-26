package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// True Positive Examples (HttpOnly not set or set to false)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_1() {
	// Basic case: Creating a cookie store without setting HttpOnly
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	// ruleid: rule-gorilla-sessions-httponly-notset
	session, _ := store.Get(nil, "session-name")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_2() {
	// Explicitly setting HttpOnly to false
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		// ruleid: rule-gorilla-sessions-httponly-notset
		HttpOnly: false,
	}
	session, _ := store.Get(nil, "session-name")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_3() {
	// Setting options but omitting HttpOnly
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	store.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400,
		// HttpOnly is not set, defaults to false
	}
	// ruleid: rule-gorilla-sessions-httponly-notset
	session, _ := store.Get(nil, "session-name")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_4() {
	// Using multiple keys but still not setting HttpOnly
	store := sessions.NewCookieStore(
		[]byte("authentication-key"),
		[]byte("encryption-key"),
	)
	// ruleid: rule-gorilla-sessions-httponly-notset
	session, _ := store.Get(nil, "complex-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_5() {
	// Setting HttpOnly to false in a handler function
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		store := sessions.NewCookieStore([]byte("secret-key"))
		store.Options = &sessions.Options{
			// ruleid: rule-gorilla-sessions-httponly-notset
			HttpOnly: false,
		}
		session, _ := store.Get(r, "user-session")
		session.Values["authenticated"] = true
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_6() {
	// Setting session options directly when getting the session
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/set-session", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		// ruleid: rule-gorilla-sessions-httponly-notset
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: false,
		}
		session.Values["key"] = "value"
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_7() {
	// Using a FilesystemStore without setting HttpOnly
	store := sessions.NewFilesystemStore("./sessions", []byte("secret-key"))
	// ruleid: rule-gorilla-sessions-httponly-notset
	session, _ := store.Get(nil, "filesystem-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_8() {
	// Using a custom secure cookie without HttpOnly
	var hashKey = []byte("very-secret-hash-key")
	var blockKey = []byte("a-lot-secret-block-key")
	var s = securecookie.New(hashKey, blockKey)
	
	// ruleid: rule-gorilla-sessions-httponly-notset
	store := &sessions.CookieStore{
		Codecs: []securecookie.Codec{s},
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400,
			// HttpOnly not set
		},
	}
	session, _ := store.Get(nil, "custom-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_9() {
	// Overriding session options at save time
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/override", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["user"] = "username"
		// ruleid: rule-gorilla-sessions-httponly-notset
		session.Options.HttpOnly = false
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_10() {
	// Creating a new session with default options and then modifying
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/modify", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.New(r, "new-session")
		// ruleid: rule-gorilla-sessions-httponly-notset
		session.Options.HttpOnly = false
		session.Values["created"] = time.Now().String()
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_11() {
	// Using a Redis store without setting HttpOnly
	// Note: This is just for demonstration, actual implementation would require the redis package
	type RedisStore struct {
		*sessions.CookieStore
	}
	
	store := &RedisStore{
		CookieStore: sessions.NewCookieStore([]byte("redis-secret")),
	}
	// ruleid: rule-gorilla-sessions-httponly-notset
	session, _ := store.Get(nil, "redis-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_12() {
	// Setting HttpOnly to false conditionally
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/conditional", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		isDebug := true // This could be from a config or environment variable
		
		if isDebug {
			// ruleid: rule-gorilla-sessions-httponly-notset
			session.Options.HttpOnly = false
		}
		
		session.Values["debug"] = isDebug
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_13() {
	// Creating a store with multiple options but HttpOnly is false
	store := sessions.NewCookieStore([]byte("secret-key"))
	store.Options = &sessions.Options{
		Path:     "/app",
		Domain:   "example.com",
		MaxAge:   86400 * 7,
		Secure:   true, // Using secure but not HttpOnly
		SameSite: http.SameSiteStrictMode,
		// ruleid: rule-gorilla-sessions-httponly-notset
		HttpOnly: false,
	}
	session, _ := store.Get(nil, "complex-options")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_14() {
	// Using a function to configure options but not setting HttpOnly
	configureStore := func() *sessions.CookieStore {
		store := sessions.NewCookieStore([]byte("secret-key"))
		store.Options = &sessions.Options{
			Path:   "/",
			MaxAge: 3600,
			// HttpOnly not set
		}
		return store
	}
	
	store := configureStore()
	// ruleid: rule-gorilla-sessions-httponly-notset
	session, _ := store.Get(nil, "configured-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_15() {
	// Setting options with a map-like approach (demonstrating a different pattern)
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	options := map[string]interface{}{
		"Path":   "/",
		"MaxAge": 86400,
		"Secure": true,
		// HttpOnly missing
	}
	
	storeOptions := &sessions.Options{
		Path:   options["Path"].(string),
		MaxAge: options["MaxAge"].(int),
		Secure: options["Secure"].(bool),
		// HttpOnly not set
	}
	
	store.Options = storeOptions
	// ruleid: rule-gorilla-sessions-httponly-notset
	session, _ := store.Get(nil, "map-configured")
	session.Save(nil, nil)
}
// {/fact}

// True Negative Examples (HttpOnly set to true)

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_1() {
	// Basic case: Setting HttpOnly to true
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	store.Options = &sessions.Options{
		// ok: rule-gorilla-sessions-httponly-notset
		HttpOnly: true,
	}
	session, _ := store.Get(nil, "session-name")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_2() {
	// Setting HttpOnly to true with other options
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		// ok: rule-gorilla-sessions-httponly-notset
		HttpOnly: true,
		Secure:   true,
	}
	session, _ := store.Get(nil, "session-name")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_3() {
	// Setting HttpOnly in a handler function
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		store := sessions.NewCookieStore([]byte("secret-key"))
		store.Options = &sessions.Options{
			// ok: rule-gorilla-sessions-httponly-notset
			HttpOnly: true,
		}
		session, _ := store.Get(r, "user-session")
		session.Values["authenticated"] = true
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_4() {
	// Setting session options directly when getting the session
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/set-session", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		// ok: rule-gorilla-sessions-httponly-notset
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
		}
		session.Values["key"] = "value"
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_5() {
	// Using a FilesystemStore with HttpOnly set
	store := sessions.NewFilesystemStore("./sessions", []byte("secret-key"))
	store.Options = &sessions.Options{
		// ok: rule-gorilla-sessions-httponly-notset
		HttpOnly: true,
	}
	session, _ := store.Get(nil, "filesystem-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_6() {
	// Using a custom secure cookie with HttpOnly
	var hashKey = []byte("very-secret-hash-key")
	var blockKey = []byte("a-lot-secret-block-key")
	var s = securecookie.New(hashKey, blockKey)
	
	store := &sessions.CookieStore{
		Codecs: []securecookie.Codec{s},
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   86400,
			// ok: rule-gorilla-sessions-httponly-notset
			HttpOnly: true,
		},
	}
	session, _ := store.Get(nil, "custom-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_7() {
	// Overriding session options at save time to ensure HttpOnly
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/override", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["user"] = "username"
		// ok: rule-gorilla-sessions-httponly-notset
		session.Options.HttpOnly = true
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_8() {
	// Creating a new session and setting HttpOnly
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.New(r, "new-session")
		// ok: rule-gorilla-sessions-httponly-notset
		session.Options.HttpOnly = true
		session.Values["created"] = time.Now().String()
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_9() {
	// Using a Redis store with HttpOnly set
	// Note: This is just for demonstration, actual implementation would require the redis package
	type RedisStore struct {
		*sessions.CookieStore
	}
	
	store := &RedisStore{
		CookieStore: sessions.NewCookieStore([]byte("redis-secret")),
	}
	store.Options = &sessions.Options{
		// ok: rule-gorilla-sessions-httponly-notset
		HttpOnly: true,
	}
	session, _ := store.Get(nil, "redis-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_10() {
	// Setting HttpOnly to true conditionally
	store := sessions.NewCookieStore([]byte("secret-key"))
	http.HandleFunc("/conditional", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		isProduction := true // This could be from a config or environment variable
		
		if isProduction {
			// ok: rule-gorilla-sessions-httponly-notset
			session.Options.HttpOnly = true
		} else {
			// Even in non-production, we set HttpOnly for security
			session.Options.HttpOnly = true
		}
		
		session.Values["production"] = isProduction
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_11() {
	// Creating a store with multiple options including HttpOnly
	store := sessions.NewCookieStore([]byte("secret-key"))
	store.Options = &sessions.Options{
		Path:     "/app",
		Domain:   "example.com",
		MaxAge:   86400 * 7,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		// ok: rule-gorilla-sessions-httponly-notset
		HttpOnly: true,
	}
	session, _ := store.Get(nil, "complex-options")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_12() {
	// Using a function to configure options with HttpOnly set
	configureStore := func() *sessions.CookieStore {
		store := sessions.NewCookieStore([]byte("secret-key"))
		store.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   3600,
			// ok: rule-gorilla-sessions-httponly-notset
			HttpOnly: true,
		}
		return store
	}
	
	store := configureStore()
	session, _ := store.Get(nil, "configured-session")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_13() {
	// Setting options with a map-like approach but ensuring HttpOnly is true
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	options := map[string]interface{}{
		"Path":     "/",
		"MaxAge":   86400,
		"Secure":   true,
		"HttpOnly": true,
	}
	
	storeOptions := &sessions.Options{
		Path:     options["Path"].(string),
		MaxAge:   options["MaxAge"].(int),
		Secure:   options["Secure"].(bool),
		// ok: rule-gorilla-sessions-httponly-notset
		HttpOnly: options["HttpOnly"].(bool),
	}
	
	store.Options = storeOptions
	session, _ := store.Get(nil, "map-configured")
	session.Save(nil, nil)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_14() {
	// Setting HttpOnly in a middleware function
	secureSessionMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			store := sessions.NewCookieStore([]byte("secret-key"))
			store.Options = &sessions.Options{
				// ok: rule-gorilla-sessions-httponly-notset
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			}
			
			session, _ := store.Get(r, "secure-session")
			session.Save(r, w)
			next.ServeHTTP(w, r)
		})
	}
	
	// Usage of the middleware
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, secure world!")
	})
	
	http.Handle("/secure", secureSessionMiddleware(handler))
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_15() {
	// Using a configuration struct to set session options
	type SessionConfig struct {
		Secret   string
		Path     string
		MaxAge   int
		HttpOnly bool
		Secure   bool
	}
	
	config := SessionConfig{
		Secret:   "secret-key",
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true, // Explicitly set to true in config
		Secure:   true,
	}
	
	store := sessions.NewCookieStore([]byte(config.Secret))
	store.Options = &sessions.Options{
		Path:   config.Path,
		MaxAge: config.MaxAge,
		// ok: rule-gorilla-sessions-httponly-notset
		HttpOnly: config.HttpOnly,
		Secure:   config.Secure,
	}
	
	session, _ := store.Get(nil, "config-session")
	session.Save(nil, nil)
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("Gorilla sessions HttpOnly test cases")
}