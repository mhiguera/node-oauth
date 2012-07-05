node-oauth
==========


How to use it
-------------

```
CONSUMER_KEY = "your_consumer_key";
CONSUMER_SECRET = "your_consumer_secret";
CALLBACK_URL = "http://application/callback";
REQUEST_URL = "http://provider/request";
ACCESS_URL = "http://provider/access";

var oauth = require('./oauth.js');
oauth.configure(CONSUMER_KEY, CONSUMER_SECRET, CALLBACK_URL);

onLogin = function(error, request, response) {
  response.header('Content-Type','text/plain; charset=utf-8'); 
  if (error) console.log("Error loging in...");
  else {
    // you are now authorized!
    var token = request.session.OAuthAccessToken;
    var tokenSecret = request.session.OAuthAccessTokenSecret
    var params = { test: 1 }
    var options = {}
    oauth.get(url, token, tokenSecret, params, {}, function(error, success) {
      //
    });
  }
}

// Handlers
getCallbackHandler = function(callback) {
  return function(request, response)  {
    authVerifier = request.query.oauth_verifier;
    requestToken = request.session.OAuthRequestToken;
    requestTokenSecret = request.session.OAuthRequestTokenSecret;
    oauth.getAccessToken(ACCESS_URL, requestToken, requestTokenSecret, authVerifier, function(error, token, tokenSecret, results) {
      if (error && callback) callback(error);
      else {
        request.session.OAuthAccessToken = token;
        request.session.OAuthAccessTokenSecret = tokenSecret;
        if (callback) callback(error, request, response);
      }
    });
  }
}

getConnectionHandler = function(callback) {
  return function(request, response) {
    oauth.getRequestToken(REQUEST_URL, function(error, token, tokenSecret, results){
      if (error && callback) callback(error);
      else {
        request.session.OAuthRequestToken       = token;
        request.session.OAuthRequestTokenSecret = tokenSecret;
        response.redirect(AUTHORIZATION_URL + request.session.OAuthRequestToken);
        if (callback) callback(error, request, response);
      }
    });
  }
}


// assuming you are using Express
var app = express.createServer();
app.get('/callback', getCallbackHandler(onLogin));
app.get('/connect', getConnectionHandler());

```

Disclaimer
----------
Both code and documentation are at a very early stage.


