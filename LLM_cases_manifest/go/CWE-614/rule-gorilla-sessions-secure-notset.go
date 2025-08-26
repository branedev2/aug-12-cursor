package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_1() {
	// Creating a session store without setting Secure to true
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["foo"] = "bar"
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_2() {
	// Using default options without setting Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore(
		[]byte("authentication-key"),
		[]byte("encryption-key"),
	)
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "user-session")
		session.Values["authenticated"] = true
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_3() {
	// Setting other options but not Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "api-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_4() {
	// Setting Secure to false explicitly
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("very-secret"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false,
	}
	http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "dashboard-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_5() {
	// Multiple stores, none with Secure set
	// ruleid: rule-gorilla-sessions-secure-notset
	store1 := sessions.NewCookieStore([]byte("key-1"))
	store2 := sessions.NewCookieStore([]byte("key-2"))
	
	http.HandleFunc("/route1", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store1.Get(r, "session1")
		session.Save(r, w)
	})
	
	http.HandleFunc("/route2", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store2.Get(r, "session2")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_6() {
	// Setting options in a separate step but forgetting Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	options := &sessions.Options{
		Path:     "/admin",
		MaxAge:   3600 * 24,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	store.Options = options
	
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "admin-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_7() {
	// Using environment variable for key but not setting Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	key := []byte(os.Getenv("SESSION_KEY"))
	if len(key) == 0 {
		key = []byte("fallback-secret-key")
	}
	
	store := sessions.NewCookieStore(key)
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "user-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_8() {
	// Using multiple keys but no Secure attribute
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore(
		[]byte("authentication-key-1"),
		[]byte("encryption-key-1"),
		[]byte("authentication-key-2"),
		[]byte("encryption-key-2"),
	)
	
	http.HandleFunc("/multi-key", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "multi-key-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_9() {
	// Creating a FilesystemStore without Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewFilesystemStore("./sessions", []byte("secret-key"))
	
	http.HandleFunc("/files", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "file-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_10() {
	// Setting session options at session level but not Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("store-secret"))
	
	http.HandleFunc("/session-options", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Options = &sessions.Options{
			Path:     "/specific",
			MaxAge:   7200,
			HttpOnly: true,
		}
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_11() {
	// Using conditional logic but never setting Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	http.HandleFunc("/conditional", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "conditional-session")
		
		if r.URL.Path == "/admin" {
			session.Options = &sessions.Options{
				Path:     "/admin",
				HttpOnly: true,
				MaxAge:   3600,
			}
		} else {
			session.Options = &sessions.Options{
				Path:     "/",
				HttpOnly: true,
				MaxAge:   7200,
			}
		}
		
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_12() {
	// Using a function to configure options but not setting Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	configureOptions := func(path string) *sessions.Options {
		return &sessions.Options{
			Path:     path,
			MaxAge:   86400,
			HttpOnly: true,
		}
	}
	
	store.Options = configureOptions("/")
	
	http.HandleFunc("/function-config", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "function-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_13() {
	// Using a map to store different session stores, none with Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	storeMap := make(map[string]*sessions.CookieStore)
	storeMap["users"] = sessions.NewCookieStore([]byte("user-secret"))
	storeMap["admin"] = sessions.NewCookieStore([]byte("admin-secret"))
	
	http.HandleFunc("/map-store", func(w http.ResponseWriter, r *http.Request) {
		storeType := "users"
		if r.URL.Path == "/admin" {
			storeType = "admin"
		}
		
		store := storeMap[storeType]
		session, _ := store.Get(r, storeType+"-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_14() {
	// Setting Secure based on a variable that's always false
	// ruleid: rule-gorilla-sessions-secure-notset
	isSecure := false
	
	store := sessions.NewCookieStore([]byte("secret-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   isSecure,
	}
	
	http.HandleFunc("/variable-secure", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "variable-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_15() {
	// Using a custom session wrapper but not setting Secure
	// ruleid: rule-gorilla-sessions-secure-notset
	type SessionManager struct {
		store *sessions.CookieStore
		name  string
	}
	
	manager := &SessionManager{
		store: sessions.NewCookieStore([]byte("manager-secret")),
		name:  "managed-session",
	}
	
	manager.store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   43200,
		HttpOnly: true,
	}
	
	http.HandleFunc("/managed", func(w http.ResponseWriter, r *http.Request) {
		session, _ := manager.store.Get(r, manager.name)
		session.Save(r, w)
	})
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_1() {
	// Setting Secure to true
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("something-very-secret"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
	}
	
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		session.Values["foo"] = "bar"
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_2() {
	// Setting all recommended security options
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("authentication-key"), []byte("encryption-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "user-session")
		session.Values["authenticated"] = true
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_3() {
	// Setting Secure at the session level
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "api-session")
		session.Options = &sessions.Options{
			Path:     "/api",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   true,
		}
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_4() {
	// Using environment variable for key and setting Secure
	// ok: rule-gorilla-sessions-secure-notset
	key := []byte(os.Getenv("SESSION_KEY"))
	if len(key) == 0 {
		key = []byte("fallback-secret-key")
	}
	
	store := sessions.NewCookieStore(key)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
	}
	
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "user-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_5() {
	// Using multiple keys with Secure set
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore(
		[]byte("authentication-key-1"),
		[]byte("encryption-key-1"),
		[]byte("authentication-key-2"),
		[]byte("encryption-key-2"),
	)
	
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
	}
	
	http.HandleFunc("/multi-key", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "multi-key-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_6() {
	// Creating a FilesystemStore with Secure set
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewFilesystemStore("./sessions", []byte("secret-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
	}
	
	http.HandleFunc("/files", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "file-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_7() {
	// Using conditional logic with Secure always true
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	http.HandleFunc("/conditional", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "conditional-session")
		
		if r.URL.Path == "/admin" {
			session.Options = &sessions.Options{
				Path:     "/admin",
				HttpOnly: true,
				MaxAge:   3600,
				Secure:   true,
			}
		} else {
			session.Options = &sessions.Options{
				Path:     "/",
				HttpOnly: true,
				MaxAge:   7200,
				Secure:   true,
			}
		}
		
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_8() {
	// Using a function to configure options with Secure set
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	configureOptions := func(path string) *sessions.Options {
		return &sessions.Options{
			Path:     path,
			MaxAge:   86400,
			HttpOnly: true,
			Secure:   true,
		}
	}
	
	store.Options = configureOptions("/")
	
	http.HandleFunc("/function-config", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "function-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_9() {
	// Using a map to store different session stores, all with Secure
	// ok: rule-gorilla-sessions-secure-notset
	storeMap := make(map[string]*sessions.CookieStore)
	
	userStore := sessions.NewCookieStore([]byte("user-secret"))
	userStore.Options = &sessions.Options{
		Path:     "/users",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
	}
	
	adminStore := sessions.NewCookieStore([]byte("admin-secret"))
	adminStore.Options = &sessions.Options{
		Path:     "/admin",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
	}
	
	storeMap["users"] = userStore
	storeMap["admin"] = adminStore
	
	http.HandleFunc("/map-store", func(w http.ResponseWriter, r *http.Request) {
		storeType := "users"
		if r.URL.Path == "/admin" {
			storeType = "admin"
		}
		
		store := storeMap[storeType]
		session, _ := store.Get(r, storeType+"-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_10() {
	// Setting Secure based on a variable that's always true
	// ok: rule-gorilla-sessions-secure-notset
	isSecure := true
	
	store := sessions.NewCookieStore([]byte("secret-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   isSecure,
	}
	
	http.HandleFunc("/variable-secure", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "variable-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_11() {
	// Using a custom session wrapper with Secure set
	// ok: rule-gorilla-sessions-secure-notset
	type SessionManager struct {
		store *sessions.CookieStore
		name  string
	}
	
	manager := &SessionManager{
		store: sessions.NewCookieStore([]byte("manager-secret")),
		name:  "managed-session",
	}
	
	manager.store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   43200,
		HttpOnly: true,
		Secure:   true,
	}
	
	http.HandleFunc("/managed", func(w http.ResponseWriter, r *http.Request) {
		session, _ := manager.store.Get(r, manager.name)
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_12() {
	// Setting options in multiple steps but including Secure
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	options := &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
	}
	
	// Add Secure separately
	options.Secure = true
	
	store.Options = options
	
	http.HandleFunc("/multi-step", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "multi-step-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_13() {
	// Using environment-based configuration with Secure always true
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	// Get environment, but always set Secure to true regardless
	env := os.Getenv("APP_ENV")
	
	if env == "development" {
		store.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400,
			HttpOnly: true,
			Secure:   true, // Still secure even in development
		}
	} else {
		store.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   true,
		}
	}
	
	http.HandleFunc("/env-config", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "env-session")
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_14() {
	// Setting session with expiration time and Secure
	// ok: rule-gorilla-sessions-secure-notset
	store := sessions.NewCookieStore([]byte("secret-key"))
	
	http.HandleFunc("/timed-session", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "timed-session")
		
		expiration := time.Now().Add(24 * time.Hour)
		maxAge := int(time.Until(expiration).Seconds())
		
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   maxAge,
			HttpOnly: true,
			Secure:   true,
		}
		
		session.Save(r, w)
	})
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_15() {
	// Using multiple session stores for different purposes, all with Secure
	// ok: rule-gorilla-sessions-secure-notset
	authStore := sessions.NewCookieStore([]byte("auth-secret"))
	authStore.Options = &sessions.Options{
		Path:     "/auth",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
	}
	
	prefStore := sessions.NewCookieStore([]byte("pref-secret"))
	prefStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 30,
		HttpOnly: true,
		Secure:   true,
	}
	
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		session, _ := authStore.Get(r, "auth-session")
		session.Save(r, w)
	})
	
	http.HandleFunc("/preferences", func(w http.ResponseWriter, r *http.Request) {
		session, _ := prefStore.Get(r, "preferences")
		session.Save(r, w)
	})
}
// {/fact}

func main() {
	fmt.Println("Server starting...")
	http.ListenAndServe(":8080", nil)
}