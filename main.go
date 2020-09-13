package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
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
	Author 		   string
	Title          string
	Selftext   	   string
	Name           string //the full name of this reddit object t1_*, t2_*, ...
	Ups            uint16
	Downs          uint16
	Permalink      string //the comments
	URL            string
	PublicDescHTML string `json:"public_description_html"`
	Body		   string 
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

type ListingAndCommentChannel struct {
	Permalink	string
	ID			int
}

func homeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	fmt.Fprintf(w, "Hello.")
}

func redditAuthenticate(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	redditState, exists := os.LookupEnv("REDDIT_STATE")
	redditClientID, _ := os.LookupEnv("REDDIT_CLIENT_ID")
	redirectURL, _ := os.LookupEnv("REDDIT_URL_REDIRECT")
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
	q.Add("redirect_uri", redirectURL)
	q.Add("duration", "temporary")
	q.Add("scope", "identity history mysubreddits read wikiread")
	req.URL.RawQuery = q.Encode()
	w.Write([]byte(req.URL.String()))
}

func redditCallback(w http.ResponseWriter, r *http.Request, db *sql.DB) {
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

func getRedditBasicInfo(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	client := &http.Client{}

	//if request header does not contain "access-token", return unauthorized
	if r.Header.Get("access-token") == "" {
		log.Println("No access token")
		http.Error(w, "No access token", http.StatusUnauthorized)
	}

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://oauth.reddit.com/api/v1/me"), nil)
	req.Header.Add("User-Agent", "web:uncluttered:v0.0 (by /u/maryanahermawan)")
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", r.Header.Get("access-token")))
	resp, err := client.Do(req)

	if err != nil {
		//if Reddit reject, return error message in body and original status
		fmt.Println("Error is ", err.Error())
		http.Error(w, err.Error(), resp.StatusCode)
	}
	body, _ := ioutil.ReadAll(resp.Body)

	var redditBasicInfo RedditBasicInfo
	json.Unmarshal(body, &redditBasicInfo)

	//get user's subreddits
	req, _ = http.NewRequest("GET", fmt.Sprintf("https://oauth.reddit.com/subreddits/mine/subscriber"), nil)
	req.Header.Add("User-Agent", "web:uncluttered:v0.0 (by /u/maryanahermawan)")
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", r.Header.Get("access-token")))
	resp, err = client.Do(req)
	if err != nil {
		//if Reddit reject, return error message in body and original status
		fmt.Println("Error 2 is ", err.Error())
		http.Error(w, err.Error(), resp.StatusCode)
	}
	body, _ = ioutil.ReadAll(resp.Body)

	var subreddits RedditResponse
	json.Unmarshal(body, &subreddits)
	redditBasicInfo.SubredditSubscription = subreddits
	json.NewEncoder(w).Encode(&redditBasicInfo)
 
	//Insert user and subreddit names into DB in doesn't exist:
	queryStmt := `SELECT id, username FROM users WHERE username =$1` 
	insertStmt := `INSERT INTO users (username) VALUES ($1) returning id`
	var id int
	var username string
	switch err = db.QueryRow(queryStmt, redditBasicInfo.Name).Scan(&id, &username); err {
		case sql.ErrNoRows:
			fmt.Println("New username>", redditBasicInfo.Name)
			var id int
			err := db.QueryRow(insertStmt, redditBasicInfo.Name).Scan(&id)
			if err != nil {
				panic(err)
			}
		case nil:
			fmt.Println("Username previously saved in DB; ID>", id)
		default:
			panic(err)
	}
	
	//update subreddits table:
	queryStmt = `SELECT name FROM subreddits WHERE name =$1` 
	insertStmt = `INSERT INTO subreddits (name) VALUES ($1) returning id`;
	for _, sr := range subreddits.Data.Children {
		row := db.QueryRow(queryStmt, sr.Data.URL)
		fmt.Println("DEBUG", sr.Data.URL)
		var name string
		switch err := row.Scan(&name); err {
			case sql.ErrNoRows:
				fmt.Println("New subreddit not in DB yet> ",  sr.Data.URL)
				var id int
				err := db.QueryRow(insertStmt, sr.Data.URL).Scan(&id)
				if err != nil {
					panic(err)
				}
			case nil:
				fmt.Println("Subreddit previously saved in DB> ", id)
			default:
				panic(err)
		}
	}

	//update subreddit_subscriptions table
	queryStmt = `SELECT id FROM users_subscription WHERE username =$1 and subreddit_name=$2` 
	insertStmt = `INSERT INTO users_subscription (username, subreddit_name) VALUES ($1, $2) returning id`;
	for _, sr := range subreddits.Data.Children {
		row := db.QueryRow(queryStmt, username, sr.Data.URL)
		var id int
		switch err := row.Scan(&id); err {
			case sql.ErrNoRows:
				fmt.Printf("DEBUG username is %s", username)
				fmt.Printf("New subscription for user:%s subreddit %s> ", username, sr.Data.URL)
				var id int
				err := db.QueryRow(insertStmt, username, sr.Data.URL).Scan(&id)
				if err != nil {
					panic(err)
				}
				fmt.Println("The new subscription inserted; ID is ", id)
			case nil:
				fmt.Println("Subscription previously saved in DB> ", id)
			default:
				panic(err)
		}
	}
}

func getRedditHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	popularityType := r.URL.Path[len("/api/reddit/"):]

	subreddit, ok := r.URL.Query()["subreddit"]
	if !ok {
		log.Println("Url Param 'subreddit' is missing")
		http.Error(w, "Compulsory URL Param subreddit is missing", http.StatusBadRequest)
	}
	srArray := strings.Split(subreddit[0], ",")

	period, periodOk := r.URL.Query()["period"]
	if !periodOk {
		log.Println("Url Param 'period' is missing")
		period = append(period, "week") //Default value
	}

	listingCount, ok := r.URL.Query()["count"]
	if !ok {
		listingCount = append(listingCount, strconv.Itoa(3))
	}
	accessToken := r.Header.Get("access-token")

	fmt.Println("DEBUG SUBREDDIT ARRAY has", len(srArray))
	listingAndCommentChan := make (chan ListingAndCommentChannel, 3*len(srArray)) //there are N*3 listings(N=number of subreddits)
	listingToHandler := make (chan RedditResponse, len(srArray))
	for _, sr := range srArray {
		go getRedditListingWorker(accessToken, db, sr, popularityType, period[0], listingCount[0], listingAndCommentChan, listingToHandler)
		go getRedditCommentWorker(accessToken, db, listingAndCommentChan)
	}

	var listingArray []RedditResponse

	for i:=0; i<len(srArray); i++ {
		listingArray = append(listingArray, <-listingToHandler)
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(&listingArray); err != nil {
		log.Println(err)
	}
}

func getRedditListingWorker(accessToken string, db *sql.DB, sr string, popularityType string, t string, count string, 
	listingToCommentWorker chan ListingAndCommentChannel, listingToHandler chan RedditResponse) {
	fmt.Println("The beginning of LISTING worker")
	client := &http.Client{}

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://oauth.reddit.com/r/%s/%s/.json?t=%s&limit=%s", sr, popularityType, t, count), nil)
	req.Header.Add("User-Agent", "web:uncluttered:v0.0 (by /u/maryanahermawan)")
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		// handle error
		log.Println("error in getting reddit listing: ", err)
	}

	// resp.Body = http.MaxBytesReader(w, resp.Body, 1048576)
	dec := json.NewDecoder(resp.Body)
	var redditResponse RedditResponse
	if err := dec.Decode(&redditResponse); err != nil {
		log.Printf("error decoding body: %q", resp.Body)
		log.Printf("error: %v", err)
		return
	}

	//update handler of the listing response
	listingToHandler <- redditResponse
	//update top_listings table and update channel to comment-worker:
	queryStmt := `SELECT id FROM top_listings WHERE reddit_id =$1` 
	insertStmt := `INSERT INTO top_listings (subreddit_name, reddit_id, listing_title, permalink, selftext, url, author) VALUES ($1, $2, $3, $4, $5, $6, $7) returning id`;
	for _, listing :=  range redditResponse.Data.Children {
		listingData := listing.Data
		
		row := db.QueryRow(queryStmt, listingData.Name)
		var id int
		switch err := row.Scan(&id); err {
			case sql.ErrNoRows:
				fmt.Println("Inserting listing for subredditname : ", listingData.Subreddit)
				err := db.QueryRow(insertStmt, fmt.Sprintf("/r/%s/", listingData.Subreddit), listingData.Name, listingData.Title, listingData.Permalink, listingData.Selftext, listingData.URL, listingData.Author).Scan(&id)
				if err != nil {
					panic(err)
				}
				fmt.Println("Listing inserted; ID is ", id)
			case nil:
				fmt.Println("Listing previously saved in DB> ", id)
			default:
				panic(err)
		}

		//Send listing.Data.Permalink, id (obtain from DB actions above) to channel
		fmt.Println("Sending to Comment worker, for listingtitle", listing.Data.Title)
		listingToCommentWorker <- ListingAndCommentChannel{Permalink: listing.Data.Permalink, ID: id}
	}
	fmt.Println("The END of LISTING worker")
}


func getRedditCommentWorker(accessToken string, db *sql.DB, inChan chan ListingAndCommentChannel)  {
	fmt.Println("The beginning of COMMENT worker")
	for {
		select {
		case listingInfo := <- inChan:
			fmt.Println("Comment worker just received from listing worker")
			req, _ := http.NewRequest("GET", fmt.Sprintf("https://oauth.reddit.com%s.json?sort=top&limit=3", listingInfo.Permalink), nil)
			req.Header.Add("User-Agent", "web:uncluttered:v0.0 (by /u/maryanahermawan)")
			req.Header.Add("Authorization", fmt.Sprintf("bearer %s", accessToken))

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				panic(err)
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}
			var postAndCommentResp []RedditResponse
			json.Unmarshal(body, &postAndCommentResp)

			var commentResp []RedditEntity
			for _, item := range postAndCommentResp {
				if item.Data.Children[0].Kind == "t1" {
					commentResp = item.Data.Children
				} else {
					commentResp = []RedditEntity {
						RedditEntity{},
					}
				}
			}
			
			queryStmt := `SELECT id FROM listing_comments WHERE comment_id =$1` 
			insertStmt := `INSERT INTO listing_comments (listing_id, comment_body, comment_id, author) VALUES ($1, $2, $3, $4) returning id`;
			for _, commentItem := range commentResp {
				row := db.QueryRow(queryStmt, listingInfo.ID)
				var id int
				switch err := row.Scan(&id); err {
					case sql.ErrNoRows:
						var id int
						err := db.QueryRow(insertStmt, listingInfo.ID, commentItem.Data.Body, commentItem.Data.Name, commentItem.Data.Author).Scan(&id)
						if err != nil {
							panic(err)
						}
						fmt.Println("New comment inserted; ID is ", id)
					case nil:
						fmt.Println("Comment previously saved in DB> ", id)
					default:
						panic(err)
				}
			}
		}
	}
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

func facebookAuthenticate(w http.ResponseWriter, r *http.Request, db *sql.DB) {
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
		ClientID:     fbClientID,
		ClientSecret: fbClientSecret,
		Scopes:       []string{"public_profile", "email", "user_posts"},
		Endpoint:     Facebook,
		RedirectURL:  redirectURL,
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

func corsHandler(fn func(http.ResponseWriter, *http.Request, *sql.DB), db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "OPTIONS":
			//handle preflight in here; OPTIONS will return status 200
			w.Header().Add("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Access-Control-Max-Age", "3600")
			w.Header().Add("Access-Control-Allow-Origin", "*")
			w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Add("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-Requested-With, remember-me, X-CSRF-Token, access-token, code, state")
			return
		default:
			//other methods still need "Access-Control-Allow-Origin"
			w.Header().Add("Access-Control-Allow-Origin", "*")
			fn(w, r, db)
			return
		}
	}
}

func main() {
	godotenv.Load()
	host, exists := os.LookupEnv("DB_HOST")
	port, _ := os.LookupEnv("DB_PORT")
	user, _ := os.LookupEnv("DB_USER")
	password, _ := os.LookupEnv("DB_PASSWORD")
	dbname, _ := os.LookupEnv("DB_NAME")
	if !exists {
		log.Println("File .env not found")
	}
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	//sql.Open does not open new connection
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/api/", corsHandler(homeHandler, db))
	http.HandleFunc("/api/reddit/", corsHandler(getRedditHandler, db))
	http.HandleFunc("/api/reddit/authenticate", corsHandler(redditAuthenticate, db))
	http.HandleFunc("/api/reddit_callback", corsHandler(redditCallback, db))
	http.HandleFunc("/api/reddit_basic_info", corsHandler(getRedditBasicInfo, db))

	// http.HandleFunc("/", homeHandler)
	// http.HandleFunc("/reddit/", getRedditHandler)
	// http.HandleFunc("/reddit/authenticate", redditAuthenticate)
	// http.HandleFunc("/reddit_callback", redditCallback)
	// http.HandleFunc("/reddit_basic_info", getRedditBasicInfo)
	// http.HandleFunc("/fb/authenticate", corsHandler(facebookAuthenticate))
	// http.HandleFunc("/fb_callback", corsHandler(fbCallback))
	log.Fatal(http.ListenAndServe(":80", nil))
}
