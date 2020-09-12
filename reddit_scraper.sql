CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL
);

CREATE TABLE subreddits (
	id SERIAL PRIMARY KEY,
	name TEXT UNIQUE NOT NULL
);

CREATE TABLE users_subscription (
	id SERIAL PRIMARY KEY,
	username TEXT,
	subreddit_name TEXT,
  	CONSTRAINT fk_username
  		FOREIGN KEY(username) 
  			REFERENCES users(username),
	CONSTRAINT fk_sr
		FOREIGN KEY(subreddit_name) 
			REFERENCES subreddits(name)
);

CREATE TABLE top_listings (
	id SERIAL PRIMARY KEY,
	scraping_date DATE NOT NULL DEFAULT CURRENT_DATE,
	subreddit_name TEXT NOT NULL,
	reddit_id TEXT NOT NULL,
	listing_title TEXT NOT NULL,
	permalink TEXT,
	selftext TEXT,
	url TEXT,
	author TEXT NOT NULL,
	CONSTRAINT fk_listing_sr
  		FOREIGN KEY(subreddit_name) 
  			REFERENCES subreddits(name)
);

CREATE TABLE listing_comments (
	id SERIAL PRIMARY KEY,
	listing_id SERIAL,
	comment_id TEXT NOT NULL,
	comment_body TEXT NOT NULL,
	author TEXT NOT NULL,
	CONSTRAINT fk_reddit_id
  		FOREIGN KEY(listing_id) 
  			REFERENCES top_listings(id)
);

CREATE TABLE related_subreddits (
	id SERIAL PRIMARY KEY,
	author TEXT NOT NULL,
	related_subreddit TEXT
);

CREATE TABLE related_listings (
	id SERIAL PRIMARY KEY,
	author TEXT NOT NULL,
	score INT NOT NULL,
	selftext TEXT,
	url TEXT
);