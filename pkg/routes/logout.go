package routes

import (
	"net/http"
	"net/url"
	"os"
)

// LogoutHandler actually handles only OAUTH0 logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	domain := os.Getenv("OAUTH0_PROVIDER_URL")

	logoutUrl, err := url.Parse(domain)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logoutUrl.Path += "v2/logout"
	parameters := url.Values{}

	var scheme string
	if r.TLS == nil {
		scheme = "http"
	} else {
		scheme = "https"
	}

	returnTo, err := url.Parse(scheme + "://" +  r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", os.Getenv("OAUTH0_CLIENT_ID"))
	logoutUrl.RawQuery = parameters.Encode()

	http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
}