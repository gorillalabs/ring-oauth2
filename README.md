# Ring-OAuth2

[![Build Status](https://travis-ci.org/gorillalabs/ring-oauth2.svg?branch=master)](https://travis-ci.org/gorillalabs/ring-oauth2)

[Ring](https://github.com/ring-clojure/ring) middleware that acts as a [OAuth 2.0](https://oauth.net/2/) client. This is used
for authenticating and integrating with third party website, like
Twitter, Facebook and GitHub.


## Installation

To install, add the following to your project `:dependencies`:

[![Clojars Project](https://img.shields.io/clojars/v/gorillalabs/ring-oauth2.svg)](https://clojars.org/gorillalabs/ring-oauth2)

## Usage

The middleware function to use is `ring.middleware.oauth2/wrap-oauth2`.
This takes a Ring handler, a map of profiles, and optional options
as arguments. Each profile has a key to identify it,
and a map of options that define how
to authorize against a third-party service.

The options define which strategy to use to create and verify state
(which secures the communication to the OAuth provider):

* **Session based state management strategy** (default): This will create a random
state in the session and compare state from requests to the session state.

* **Signed token state management strategy**: This will create a signed token (JWT)
(using a private key) to be transferred.
The token is validated by checking signature (using the public key) and claims.

Here's an example that provides authentication with GitHub using
default options (aka session based state management, storing access-keys to session,
embedding them into the request):

```clojure
(require '[ring.middleware.oauth2 :refer [wrap-oauth2])

(def handler
  (wrap-oauth2
   routes
   {:github
    {:authorize-uri    "https://github.com/login/oauth/authorize"
     :access-token-uri "https://github.com/login/oauth/access_token"
     :client-id        "abcabcabc"
     :client-secret    "xyzxyzxyzxyzxyz"
     :scopes           ["user:email"]
     :launch-uri       "/oauth2/github"
     :redirect-uri     "/oauth2/github/callback"
     :landing-uri      "/"}}))
```

And here's the same example using token-based state management:

```clojure
(require '[ring.middleware.oauth2 :refer [wrap-oauth2]]
         '[buddy.core.keys :as keys]
         '[clj-time.core]
         '[ring.middleware.oauth2.strategy.signed-token :as token])

(def private-key (keys/private-key "resources/certs/privkey.pem" "password"))
(def public-key (keys/public-key "resources/certs/pubkey.pem"))
(def expiry-period1h (clj-time.core/hours 1))

(def signed-token-sms (token/signed-token-sms public-key private-key expiry-period1h))


(def handler
  (wrap-oauth2
   routes
   {:github
    {:authorize-uri    "https://github.com/login/oauth/authorize"
     :access-token-uri "https://github.com/login/oauth/access_token"
     :client-id        "abcabcabc"
     :client-secret    "xyzxyzxyzxyzxyz"
     :scopes           ["user:email"]
     :launch-uri       "/oauth2/github"
     :redirect-uri     "/oauth2/github/callback"
     :landing-uri      "/"}}
   :state-management-strategy signed-token-sms))
```


The profile has a lot of options, and all have a necessary
function. Let's go through them one by one.

The first two keys are the authorize and access token URIs:

* `:authorize-uri`
* `:access-token-uri`

These are URLs provided by the third-party website. If you look at the
OAuth documentation for the site you're authenticating against, it
should tell you which URLs to use.

Next is the client ID and secret:

* `:client-id`
* `:client-secret`

When you register your application with the third-party website, these
two values should be provided to you. Note that these should not be
kept in source control, especially the client secret!

Optionally you can define the scope or scopes of the access you want:

* `:scopes`

These are used to ask the third-party website to provide access to
certain information. In the previous example, we set the scopes to
`["user:email"]`; in other words, we want to be able to access the
user's email address. Scopes are a vector of either strings or
keywords, and are specific to the website you're authenticating
against.

The next URIs are internal to your application:

* `:launch-uri`
* `:redirect-uri`
* `:landing-uri`

The launch URI kicks off the authorization process. Your log-in link
should point to this address, and it should be unique per profile.

The redirect URI provides the internal callback. It can be any
relative URI as long as it is unique. It can also be an absolute URI like
`https://loadbalanced-url.com/oauth2/github/callback`

The landing URI is where the middleware redirects the user when the
authentication process is complete. This could just be back to the
index page, or it could be to the user's account page.

* `:basic-auth?`

This is an optional parameter, which defaults to false.
If set to true, it includes the client-id and secret as a header
`Authorization: Basic base64(id:secret)` as recommended by [the specification][].

**If using the session-based state management strategy:**
Please note, you should enable cookies to be sent with cross-site requests,
in order to make the callback request handling work correctly, eg:
```clojure
(wrap-defaults (-> site-defaults (assoc-in [:session :cookie-attrs :same-site] :lax)))
```


[the specification]: https://tools.ietf.org/html/rfc6749#section-2.3.1

## Workflow diagram

The following image is a workflow diagram that describes the OAuth2
authorization process for Ring-OAuth2. It should give you an overview
of how all the different URIs interact.

![OAuth2 Workflow](https://github.com/weavejester/ring-oauth2/raw/master/docs/workflow.png)

## License

Copyright © 2017 James Reeves

Released under the MIT License.
