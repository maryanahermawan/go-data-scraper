package main

import (
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var redditBearerToken RedditBearerTokenResponse

//RedditResponse :
type RedditResponse struct {
	kind string //Listing, etc..
	Data RedditResponseData
}

//RedditResponseData : how many entries returned
type RedditResponseData struct {
	Dist     uint16
	Children []RedditEntity
}

//RedditEntity : kind is either t1, t2 ... t6
type RedditEntity struct {
	Kind string
	Data RedditData
}

//RedditData : fields are picked
type RedditData struct {
	Subreddit      string
	AuthorFullname string `json:"author_fullname"`
	Title          string
	SelftextHTML   string `json:"selftext_html"`
	Name           string //the full name of this reddit object t1_*, t2_*, ...
	Ups            uint16
	Downs          uint16
	Permalink      string //the comments
	URL            string
	PublicDescHTML string `json:"public_description_html"`
}

//RedditBearerTokenResponse : Reddit response with bearer token
type RedditBearerTokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string
}

//RedditBasicInfo : auth callback return basic info
type RedditBasicInfo struct {
	Name                  string
	SubredditSubscription RedditResponse
}

func getRedditListingHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	popularityType := r.URL.Path[len("/reddit/"):]

	period, ok := r.URL.Query()["period"]
	if !ok {
		log.Println("Url Param 'period' is missing")
		period = append(period, "week") //Default value
	}

	listingCount, ok := r.URL.Query()["count"]
	if !ok {
		listingCount = append(listingCount, strconv.Itoa(3))
	}
	log.Println("Popularity Period count", popularityType, period, listingCount)
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://oauth.reddit.com/r/golang/%s/.json?t=%s&limit=%s", popularityType, period[0], listingCount[0]), nil)
	req.Header.Add("User-Agent", "web:learn-golang:v0.0 (by /u/maryanahermawan)")
	resp, err := client.Do(req)
	if err != nil {
		// handle error
	}

	resp.Body = http.MaxBytesReader(w, resp.Body, 1048576)
	dec := json.NewDecoder(resp.Body)
	var redditResponse RedditResponse
	if err := dec.Decode(&redditResponse); err != nil {
		log.Println(err)
		return
	}
	log.Println("Response header is", resp.Header)
	enc := json.NewEncoder(w)
	if err := enc.Encode(&redditResponse); err != nil {
		log.Println(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Go web scraper backend.")
}

func redditAuthenticate(w http.ResponseWriter, r *http.Request) {
	redditState, exists := os.LookupEnv("REDDIT_STATE")
	redditClientID, _ := os.LookupEnv("REDDIT_CLIENT_ID")
	if !exists {
		log.Println("File .env not found")
	}

	req, err := http.NewRequest("GET", "https://www.reddit.com/api/v1/authorize", nil)
	if err != nil {
		log.Println("Error building request:", err)
	}

	q := req.URL.Query()
	q.Add("client_id", redditClientID)
	q.Add("response_type", "code")
	q.Add("state", redditState)
	q.Add("redirect_uri", "http://127.0.0.1:8080/reddit_callback")
	q.Add("duration", "temporary")
	q.Add("scope", "identity,mysubreddits,read")
	req.URL.RawQuery = q.Encode()
	w.Write([]byte(req.URL.String()))
}

func redditCallback(w http.ResponseWriter, r *http.Request) {
	redditSecret, exists := os.LookupEnv("REDDIT_AUTHORIZATION")
	redditState, _ := os.LookupEnv("REDDIT_STATE")
	frontEndURL, _ := os.LookupEnv("FRONTEND_URL_REDIRECT_TO_RETURN_ACCESS_TOKEN")
	redirectURL, _ := os.LookupEnv("REDDIT_URL_REDIRECT")
	if !exists {
		log.Println("File .env not found")
	}

	error, ok := r.URL.Query()["error"]
	log.Println("Error field's ok is", error, len(error), ok)

	//A one-time use code that may be exchanged for a bearer token:
	code, ok := r.URL.Query()["code"]
	log.Println("code field's ok is", ok)

	state, ok := r.URL.Query()["state"]
	log.Println("state field's ok is", ok)

	if !ok || len(error) > 0 {
		log.Println("Error is returned from Reddit")
		http.Error(w, error[0], http.StatusUnauthorized)
	}

	if state[0] != redditState {
		log.Println("State returned is unknown")
		http.Error(w, "Unknown state", http.StatusUnauthorized)
	}

	client := &http.Client{}
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURL)
	data.Set("code", code[0])

	//Get access token; the payload is urlencoded
	req, _ := http.NewRequest("POST", fmt.Sprintf("https://www.reddit.com/api/v1/access_token"), strings.NewReader(data.Encode()))
	req.Header.Add("Authorization", redditSecret)
	req.Header.Add("User-Agent", "web:uncluttered:v0.0(by /u/maryanahermawan)")
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error returned from POST request to reddit.com/api/v1/access_token.")
		http.Error(w, "Fail getting bearer token", http.StatusUnauthorized)
	}

	body, respError := ioutil.ReadAll(resp.Body)
	log.Println("Raw body is", string(body))

	var m RedditBearerTokenResponse
	unmarshalError := json.Unmarshal(body, &m)
	if respError != nil || unmarshalError != nil {
		log.Println("Error from reading response body or unmarshaling response body", respError, unmarshalError)
		http.Error(w, "Error getting response body", http.StatusUnauthorized)
	}
	redditBearerToken = m //store access token in server

	// Finally, send a response to redirect the user to the "welcome" page
	// with the access token
	w.Header().Set("Location", frontEndURL+"/reddit_dashboard?access_token="+redditBearerToken.AccessToken)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func getRedditBasicInfo(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{}

	//get username
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://oauth.reddit.com/api/v1/me"), nil)
	req.Header.Add("User-Agent", "web:uncluttered:v0.0 (by /u/maryanahermawan)")
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", redditBearerToken.AccessToken))
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)

	var redditBasicInfo RedditBasicInfo
	json.Unmarshal(body, &redditBasicInfo)

	//get subreddits
	req, _ = http.NewRequest("GET", fmt.Sprintf("https://oauth.reddit.com/subreddits/mine/subscriber"), nil)
	req.Header.Add("User-Agent", "web:uncluttered:v0.0 (by /u/maryanahermawan)")
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", redditBearerToken.AccessToken))
	resp, _ = client.Do(req)
	body, _ = ioutil.ReadAll(resp.Body)
	// log.Println("Raw body is", string(body))

	var subreddits RedditResponse
	json.Unmarshal(body, &subreddits)
	redditBasicInfo.SubredditSubscription = subreddits
	json.NewEncoder(w).Encode(&redditBasicInfo)
}

// func getLatestFbPostsHandler(w http.ResponseWriter, r *http.Request){
// 	console.log("Init is called")
// 	FB.api(
// 		'/me',
// 		'GET',
// 		{ "fields": "id,name,about,posts" },
// 		function (response) {
// 			// Insert your code here
// 			console.log("me response is", response)
// 		}
// 	);
// }

func facebookAuthenticate(w http.ResponseWriter, r *http.Request) {
	fbClientID, exists := os.LookupEnv("FB_CLIENT_ID")
	fbClientSecret, _ := os.LookupEnv("FB_CLIENT_SECRET")
	fbState, _ := os.LookupEnv("FB_STATE")
	// frontEndURL, _ := os.LookupEnv("FRONTEND_URL_REDIRECT_TO_RETURN_ACCESS_TOKEN")
	redirectURL, _ := os.LookupEnv("FB_URL_REDIRECT")
	if !exists {
		log.Println("File .env not found")
	}
	var Facebook = oauth2.Endpoint{
		AuthURL:  "https://www.facebook.com/v2.7/dialog/oauth",
		TokenURL: "https://graph.facebook.com/v2.7/oauth/access_token",
	}
	conf := &oauth2.Config{
		ClientID: fbClientID,
		ClientSecret: fbClientSecret,
		Scopes: []string{"public_profile", "email", "user_posts"},
		Endpoint: Facebook,
		RedirectURL: redirectURL,
	}

	req, err := http.NewRequest("GET", conf.Endpoint.AuthURL, nil)
	if err != nil {
		log.Println("Error building request:", err)
	}

	q := req.URL.Query()
	q.Add("client_id", conf.ClientID)
	q.Add("response_type", "code")
	q.Add("state", fbState)
	q.Add("redirect_uri", conf.RedirectURL)
	q.Add("scope", strings.Join(conf.Scopes, " "))
	req.URL.RawQuery = q.Encode()
	w.Write([]byte(req.URL.String()))
}


func corsHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// if r.Method == "OPTIONS" {
		//handle preflight in here
		log.Print("preflight detected: ", r.Header)
		w.Header().Add("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Access-Control-Max-Age", "3600")
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Add("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-Requested-With, remember-me, X-CSRF-Token, Authorization, code, state")
		// }
		fn(w, r)
		return
	}
}

func main() {
	godotenv.Load()
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/reddit/", corsHandler(getRedditListingHandler))
	
	http.HandleFunc("/reddit/authenticate", corsHandler(redditAuthenticate))
	http.HandleFunc("/reddit_callback", corsHandler(redditCallback))
	http.HandleFunc("/fb/authenticate", corsHandler(facebookAuthenticate))
	// http.HandleFunc("/fb_callback", corsHandler(fbCallback))
	// http.HandleFunc("/", corsHandler(homeHandler))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
