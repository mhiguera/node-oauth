var crypto = require('crypto');
var http = require('http');
var https = require('https');
var URL = require('url');
var QueryString = require('querystring'); 


var ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
var consumerKey, consumerSecret, callbackURL;

var configure = function(key, secret, cbURL) {
  consumerKey = key;
  consumerSecret = secret;
  callbackURL = cbURL;
}

var getRequestToken = function(requestURL, callback) {
  post(requestURL, "", "", { oauth_callback : callbackURL }, function(error, data, response) {
    if (error) callback(error);
    else {
      var results = QueryString.parse(data);
      callback(null, results['oauth_token'], results['oauth_token_secret'], results);
    }
  });
}

var getAccessToken = function(accessURL, token, tokenSecret, authVerifier, callback) {
  post(accessURL, token, tokenSecret, { oauth_verifier : authVerifier }, function(error, data, response) {
    if (error) callback(error);
    else {
      var results = QueryString.parse(data);
      callback(null, results['oauth_token'], results['oauth_token_secret'], results);
    }
  });
}

var get = function(url, token, tokenSecret, parameters, options, callback) {
  if (typeof options == "function") { callback = options; options = {} }
  request("GET", url, token, tokenSecret, parameters, options, callback);
}

var post = function(url, token, tokenSecret, parameters, options, callback) {
  if (typeof options == "function") { callback = options; options = {} }
  request("POST", url, token, tokenSecret, parameters, options, callback);
}

var request = function(method, url, token, tokenSecret, customParameters, options, callback) {
  // Timestamp and nonce
  var timestamp = createTimestamp();
  var nonce = createNonce();

  // Flatten and set parameters
  var parameters = {
    oauth_timestamp        : timestamp,
    oauth_nonce            : nonce,
    oauth_version          : "1.0",
    oauth_signature_method : "HMAC-SHA1",
    oauth_consumer_key     : consumerKey
  }

  if (token) parameters["oauth_token"] = token;

  // URL normalization
  url = normalizeURL(url);
  parsedURL = URL.parse(url,true);

  // Parameters normalization
  urlParameters = parsedURL.query;
  customParameters = flatten(customParameters);
  for (k in urlParameters) parameters[k] = urlParameters[k];
  for (k in customParameters) parameters[k] = customParameters[k];
  parametersArray = getParametersArray(parameters);

  // Signature creation
  normalizedParameters = normalizeParametersArray(parametersArray);
  signatureBase = createSignatureBase(method, url, normalizedParameters);
  parametersArray.push(createParameter('oauth_signature', createSignature(signatureBase, tokenSecret)));

  // HTTP headers
  splitted = splitParameters(parametersArray);
  parametersArray = splitted.oauth;
  customParametersString = getStringFromParameters(splitted.body);
  body = (method == "POST")? customParametersString : "";

  httpHeaders = {
    'Authorization'  : getAuthorizationHeader(parametersArray),
    'Host'           : parsedURL.host,
    'Accept'         : "*/*",
    'Connection'     : "keep-alive",
    'User-Agent'     : "NodeJS",
    'Content-Length' : Buffer.byteLength(body),
    'Content-Type'   : "application/x-www-form-urlencoded"
  }

  // HTTP request
  secureHttp = parsedURL.protocol == "https:";
  fullPathname = (customParametersString)? parsedURL.pathname + "?" + customParametersString : parsedURL.pathname;
  var requestOptions = {
    host    : parsedURL.hostname,
    port    : parsedURL.port || (secureHttp)? 443 : 80,
    path    : (method == "POST")? parsedURL.pathname : fullPathname,
    method  : method,
    headers : httpHeaders
  }

  protocol = (secureHttp)? 'https' : 'http';
  var request = require(protocol).request(requestOptions);
  var data = "";
  var dataCallback = options.dataCallback || function(chunk) { data += chunk }
  
  // Request events
  var onRequestResponse = function(response) {
    response.setEncoding('utf8');
    response.on('data', dataCallback);
    response.on('end', function() {
      if (response.statusCode >= 200 && response.statusCode <= 299 ) callback(null, data, response)
      else if ((response.statusCode == 301 || response.statusCode == 302) && response.headers && response.headers.location) {
        request(method, response.headers.location, parameters, token, tokenSecret, callback)
      } else callback({ statusCode : response.statusCode, data : data }, data, response);
    });
  }
  request.on('response', onRequestResponse);
  request.on('error', callback);
  if (body != "") request.write(body);
  request.end();
}

// Get authorization headers
var getAuthorizationHeader = function(parametersArray) {
  arr = [];
  parametersArray.forEach(function(u) { arr.push(encode(u.name) + "=\"" + encode(u.value) +"\"") })
  return "OAuth " + arr.join(",");
}

// Timestamp and Nonce
var createTimestamp = function() {
  return Math.floor((new Date()).getTime() / 1000);
}

var createNonce = function() {
  var nonce = "";
  for (var i=0; i < 12; i++) nonce += ALPHANUMERIC.charAt(Math.floor(Math.random() * ALPHANUMERIC.length));
  return nonce;
}

// Parameters management
var createParameter = function(n, v) {
  return { name: n, value: v }
}

var getParametersArray = function(parameters) {
  arr = [];
  for (var k in parameters) arr.push(createParameter(k, parameters[k]));
  return arr;
}

var splitParameters = function(parametersArray) {
  o = { oauth: [], body: [] };
  parametersArray.forEach(function(p) { ((p.name.match('^oauth_'))? o.oauth : o.body).push(createParameter(p.name, p.value)) });
  return o;
}

var getStringFromParameters = function(parametersArray) {
  o = {}
  parametersArray.forEach(function(e) { o[e.name] = e.value });
  return QueryString.stringify(o);
}

// Normalization
var normalizeURL = function(url) {
  var parsedURL = URL.parse(url, true)
  var protocol = parsedURL.protocol;
  var port = parsedURL.port || "";
  var path = parsedURL.pathname;
  var host = parsedURL.hostname;
  if(protocol == "http" && port != 80 || protocol == "http" && port != 80 || protocol == "http" && port != 80) port = ":" + port;
  if(!path || path == "" ) path ="/";
  return protocol + "//" + host + port + path;
}

var normalizeParametersArray = function(parametersArray) {
  arr = []
  parametersArray.sort(function(n,m) {
    if (n.name == m.name) return (n.value < m.value)? -1 : 1
    else return (n.name < m.name)? -1 : 1
  });
  parametersArray.forEach(function(u) { arr.push(encode(u.name) + "=" + encode(u.value)) })
  return arr.join("&");
}

// Signature
var createSignatureBase = function(method, url, parameters) {
  return method.toUpperCase() + "&" + encode(url) + "&" + encode(parameters);
}

var createSignature = function(signatureBase, tokenSecret) {
  return crypto.createHmac("sha1", consumerSecret + "&" + encode(tokenSecret || "")).update(signatureBase).digest("base64");
}

// RFC1738 compliant encode
var encode = function(str) {
 if(str == null || str == "" ) return ""
 else return encodeURIComponent(str).replace(/\!/g, "%21").replace(/\'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/\*/g, "%2A");
}

// Object flattening
var flatten = function (o, k, t, notFirst) {
  t = t || {}
  for (var key in o) {
    keyname = (k)? k + "[" + key + "]" : key
    if (typeof o[key] == "object") arguments.callee(o[key], keyname, t, true)
    else t[keyname] = o[key]
  }
  return t;
}

exports.configure = configure
exports.getRequestToken = getRequestToken
exports.getAccessToken = getAccessToken
exports.get = get
exports.post = post
