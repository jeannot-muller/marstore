// Package marstore enables microsoft OAuth Authentication
// combined with REDIS and a RedisStore with Gorilla Sessions.
// This is currently work in progress. Don't use in production yet!
package marstore

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/no-src/redistore"
	"github.com/pkg/errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// AuthorizationCode represents an authorization code used for authentication and authorization.
type AuthorizationCode struct {
	Value string
}

// Tokens represents the data structure for storing access and refresh tokens.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// Users is a struct that represents user information. It contains various properties such as User ID,
// business phones, display name, first name, job title, email, mobile phone, office location, preferred
// language, last name, and user principal name. This struct is used to retrieve and store user information
// from the Microsoft Graph API.
type Users struct {
	UserID            string   `json:"id"`
	BusinessPhones    []string `json:"businessPhones"`
	DisplayName       string   `json:"displayName"`
	FirstName         string   `json:"givenName"`
	JobTitle          string   `json:"jobTitle"`
	Email             string   `json:"mail"`
	MobilePhone       string   `json:"mobilePhone"`
	OfficeLocation    string   `json:"officeLocation"`
	PreferredLanguage string   `json:"preferredLanguage"`
	LastName          string   `json:"surname"`
	UserPrincipleName string   `json:"userPrincipalName"`
}

// Config represents the configuration settings for the application.
//
// It includes various fields such as client ID, client secret, tenant ID,
// host names, paths, redirect port, scope, session settings, security keys,
// production mode, and CORS settings.
//
// This struct is used to initialize the application's configuration and provides
// access to the configuration values throughout the application.
type Config struct {
	ClientID         string
	ClientSecret     string
	TenantID         string
	HostNameDev      string
	HostNameProd     string
	LoginPath        string
	LandingPath      string
	ErrorPath        string
	RedirectPort     int
	RedirectPath     string
	Scope            string
	SessionName      string
	SessionMaxAge    int
	SecurityKeyCSRF  string
	SecurityKeyStore string
	IsProduction     bool
	RedisPort        int
	RedisHostName    string
	AllowOrigin      []string
	AllowMethods     []string
	AllowHeaders     []string
}

// Store is a package-level variable of type `*redistore.RediStore`. It represents the Redis store
// for session management. The `Store` variable is used to store and retrieve session data
// in the Redis database. It is initialized by the `InitializeStore` function and can be used
// in various functions throughout the package to handle session-related operations, such as
// session initialization, retrieval, and deletion.
var Store *redistore.RediStore

// InitializeStore initializes the Redis store for session management based on the provided Config.
// It creates a new RediStore with the given parameters and assigns it to the package-level Store variable.
// It registers the Users and Tokens types to allow them to be stored in the session.
// It sets the options for the store, including the session path, maximum age, http-only flag, secure flag,
// and same-site mode based on the Config.
// If an error occurs during initialization, it prints an error message and exits the program.
// Finally, it prints a message indicating that the Redis Store is running at the specified address.
// Note: This function assumes that the Redis server is running on "localhost:6379".
func InitializeStore(c Config) {
	hostname := c.RedisHostName + ":" + strconv.Itoa(c.RedisPort)
	store, err := redistore.NewRediStore(10, "tcp", hostname, "", []byte(c.SecurityKeyStore))
	if err != nil {
		fmt.Println("Error initializing Redis Store:", err)
		os.Exit(1)
	}

	gob.Register(Users{})
	gob.Register(Tokens{})

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   getSessionMaxAge(c),
		HttpOnly: true,
		Secure:   c.IsProduction,
		SameSite: getSameSiteMode(c),
	}
	fmt.Println("Redis Store running at localhost: 6379.")
	// Assign the store to the package-level Store variable
	Store = store
}

// getSessionMaxAge returns the value of the SessionMaxAge field from the Config struct.
func getSessionMaxAge(c Config) int {
	return c.SessionMaxAge
}

// RedirectURL returns the URL that should be used for redirecting based on the configuration.
// The URL is constructed using the host name, scheme, and redirect path from the Config struct.
// If the IsProduction field is false, the development host name and redirect port are used,
// and the scheme is set to "http". Otherwise, the production host name and "https" scheme are used.
// The resulting URL returns a string.
func (c Config) RedirectURL() string {
	host := c.HostNameProd
	scheme := "https"

	if !c.IsProduction {
		host = fmt.Sprintf("%s:%d", c.HostNameDev, c.RedirectPort)
		scheme = "http"
	}

	uri := url.URL{
		Host:   host,
		Scheme: scheme,
		Path:   c.RedirectPath,
	}
	return uri.String()
}

// AuthorizationURLPrefix is a constant that represents the prefix of the authorization URL.
// It is used to construct the full authorization URL by appending the necessary components.
// The constant value is "https://login.microsoftonline.com/".
const AuthorizationURLPrefix = "https://login.microsoftonline.com/"
const AuthorizationURLSuffix = "/oauth2/v2.0/authorize"
const TokenURLSuffix = "/oauth2/v2.0/token"

// GetTokens retrieves access and refresh tokens for the specified authorization code and scope,
// using the provided configuration.
//
// It constructs the necessary form values, including the code, grant type, redirect URI, client ID,
// and scope. It makes a POST request to the authorization token URL with the form values.
// If the request is successful, it reads the response body and parses it into a Tokens struct.
// The Tokens struct contains the access token, refresh token, expires in, and token type.
//
// If any error occurs during the process, it is wrapped and returned along with an empty Tokens struct.
// The error messages indicate the specific step in which the error occurred.
//
// The function requires a Config struct, which holds the necessary configuration values such as client ID,
// client secret, tenant ID, redirect URL, and more. It also requires an AuthorizationCode and a scope string.
// The AuthorizationCode is obtained after successful authentication/authorization,
// and the scope represents the requested access permissions.
//
// The function returns a Tokens struct and an error value.
// The Tokens struct contains the retrieved access and refresh tokens, while the error value
// indicates whether the token retrieval was successful or if any error occurred.
func GetTokens(
	c Config,
	authCode AuthorizationCode,
	scope string,
) (t Tokens, err error) {
	formVals := url.Values{}
	formVals.Set("code", authCode.Value)
	formVals.Set("grant_type", "authorization_code")
	formVals.Set("redirect_uri", c.RedirectURL())
	formVals.Set("scope", scope)
	if c.ClientSecret != "" {
		formVals.Set("client_secret", c.ClientSecret)
	}
	formVals.Set("client_id", c.ClientID)
	response, err := http.PostForm(AuthorizationURLPrefix+c.TenantID+TokenURLSuffix, formVals)

	if err != nil {
		return t, errors.Wrap(err, "error while trying to get tokens")
	}
	body, err := io.ReadAll(response.Body)

	if err != nil {
		return t, errors.Wrap(err, "error while trying to read token json body")
	}

	err = json.Unmarshal(body, &t)
	if err != nil {
		return t, errors.Wrap(err, "error while trying to parse token json body")
	}

	return
}

// LoginHandler handles the login process. It checks if the user is already authenticated
// and redirects them to the original URL or landing page if they are. Otherwise, it constructs
// the login URL and redirects the user to it.
func LoginHandler(w http.ResponseWriter, r *http.Request, c Config) error {
	// Check if the user is already authenticated
	session, _ := Store.Get(r, c.SessionName)
	if session.Values["access_token"] != nil {
		// User is already authenticated, redirect them to the original URL or landing page
		http.Redirect(w, r, c.LandingPath, http.StatusFound)
		return nil
	}

	// Construct the login URL with the original URL as a query parameter
	loginURL := loginRequest(c)

	// Redirect the user to the login URL
	http.Redirect(w, r, loginURL, http.StatusFound)
	return nil
}

// loginRequest constructs the login request URL for initial authentication.
func loginRequest(c Config) string {
	formVals := url.Values{}
	formVals.Set("grant_type", "authorization_code")
	formVals.Set("redirect_uri", c.RedirectURL())
	formVals.Set("scope", c.Scope)
	formVals.Set("response_type", "code")
	formVals.Set("response_mode", "query")
	formVals.Set("client_id", c.ClientID)
	// Append the original URL as a query parameter
	uri, _ := url.Parse(AuthorizationURLPrefix + c.TenantID + AuthorizationURLSuffix)
	uri.RawQuery = formVals.Encode()
	return uri.String()
}

// CallbackHandler handles the callback from the authentication provider.
// It retrieves the authorization code from the URL, gets the access and refresh tokens,
// retrieves the user information, sets the session values, saves the session,
// and finally redirects the user to the landing page.
func CallbackHandler(w http.ResponseWriter, r *http.Request, c Config) error {
	code := r.URL.Query().Get("code")
	if code == "" {
		return errors.New("no code in URL")
	}

	t, err := GetTokens(c, AuthorizationCode{Value: code}, c.Scope)
	if err != nil {
		return errors.New("error getting tokens")
	}

	authenticatedUser, err := GetUserInfo(t.AccessToken)
	if err != nil {
		return errors.New("error getting user info")
	}

	session, err := Store.Get(r, c.SessionName)
	if err != nil {
		return errors.New("error getting session")
	}

	// Set session values
	session.Values["access_token"] = t.AccessToken
	session.Values["user"] = authenticatedUser

	// Save session
	err = session.Save(r, w)
	if err != nil {
		return errors.New("error saving session")
	}

	http.Redirect(w, r, c.LandingPath, http.StatusFound)
	return nil
}

// LogoutHandler clears the auth_token cookie, invalidates the user session, deletes the session from Redis,
// and redirects the user to the home page for logout.
func LogoutHandler(w http.ResponseWriter, r *http.Request, c Config) error {
	// Clear the auth_token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0), // Set expiration date to the past
		MaxAge:   -1,              // Set MaxAge to -1 to delete the cookie
		HttpOnly: true,
	})

	// Fetch the session
	session, err := Store.Get(r, c.SessionName)
	if err != nil {
		return errors.New("Failed to get session")
	}

	// Invalidate the session
	err = session.Save(r, w)
	if err != nil {
		return errors.New("Failed to save session")
	}

	// Delete the session from Redis
	err = Store.Delete(r, w, session)
	if err != nil {
		return errors.New("Failed to delete session")
	}

	// Redirect to the home page
	http.Redirect(w, r, "https://login.microsoftonline.com/common/oauth2/v2.0/logout", http.StatusFound)
	return nil
}

// GetUserInfo retrieves the user's information from the Microsoft Graph API
// using the specified access token.
//
// The access token is used to authenticate the request to the API.
// If the access token is valid and the request is successful, the user's
// information is returned as a Users struct. Otherwise, an error is returned
// indicating the failure to get the user's information.
//
// The Users struct contains various properties representing the user's
// information such as ID, email, display name, job title, and more.
func GetUserInfo(accessToken string) (u Users, err error) {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return Users{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Users{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return Users{}, fmt.Errorf("failed to get user info: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return u, errors.Wrap(err, "error while trying to read token json body")
	}
	err = json.Unmarshal(body, &u)
	if err != nil {
		return u, errors.Wrap(err, "error while trying to parse token json body")
	}
	return u, nil
}

// getSameSiteMode returns the value of http.SameSite based on the IsProduction flag in the provided Config.
// If IsProduction is true, it returns http.SameSiteLaxMode, otherwise it also returns http.SameSiteLaxMode.
func getSameSiteMode(c Config) http.SameSite {
	if c.IsProduction {
		return http.SameSiteLaxMode
	}
	return http.SameSiteLaxMode
}

// MiddlewareFactory creates a middleware function that serves as the authorization middleware for protected routes.
// It checks if the session contains an access token and redirects to the login page if it doesn't.
// If an additional "auth_success" cookie is found, it allows the request to proceed without requiring an access token.
// It returns the middleware function that can be used in an HTTP handler chain.
//
// Parameters:
//   - c: the configuration object containing session information
//
// Returns:
//   - A middleware function that takes a http.Handler and returns a http.Handler.
func MiddlewareFactory(c Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := Store.Get(r, c.SessionName)
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Redirect(w, r, c.LoginPath, http.StatusFound)
				return
			}
			if session.Values["access_token"] == nil {
				// Check for the additional cookie
				authSuccessCookie, err := r.Cookie("auth_success")
				if err == nil && authSuccessCookie.Value == "true" {
					// Allow the request to proceed
					log.Println("Auth success cookie found, proceeding to next handler")
					next.ServeHTTP(w, r)
					return
				}
				log.Println("No access token found in session, redirecting to /login")
				http.Redirect(w, r, c.LoginPath, http.StatusFound)
				return
			}

			log.Println("Session and access token found, proceeding to next handler")
			next.ServeHTTP(w, r)
		})
	}
}

// SetupCORS sets up Cross-Origin Resource Sharing (CORS) middleware for HTTP handlers.
//
// Parameters:
//   - config: the configuration object containing CORS settings
//
// Returns:
//   - A function that can be used as middleware in an HTTP handler chain.
func SetupCORS(config Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set Access-Control-Allow-Origin from config
			for _, origin := range config.AllowOrigin {
				w.Header().Add("Access-Control-Allow-Origin", origin)
			}
			// Set Access-Control-Allow-Methods from config
			for _, method := range config.AllowMethods {
				w.Header().Add("Access-Control-Allow-Methods", method)
			}
			// Set Access-Control-Allow-Headers from config
			for _, header := range config.AllowHeaders {
				w.Header().Add("Access-Control-Allow-Headers", header)
			}
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFProtection generates middleware to protect against CSRF attacks.
// The middleware adds CSRF tokens to all HTML forms in the application
// and verifies the tokens on form submission.
//
// Parameters:
//   - c: the configuration object with security key for CSRF protection
//
// Returns:
//   - A function that can be used as middleware in an HTTP handler chain.
func CSRFProtection(c Config) func(http.Handler) http.Handler {
	return csrf.Protect(
		[]byte(c.SecurityKeyCSRF),
		csrf.Secure(c.IsProduction), // Ensure CSRF tokens are only sent over HTTPS
	)
}
