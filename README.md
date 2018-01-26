# Ring-OAuth2

[![Build Status](https://travis-ci.org/gorillalabs/ring-oauth2.svg?branch=master)](https://travis-ci.org/gorillalabs/ring-oauth2/)

[Ring](https://github.com/ring-clojure/ring) middleware that acts as
an [OAuth 2.0](https://oauth.net/2/) client. This is used
for authenticating and integrating with third party website, like
Twitter, Facebook and GitHub.

This is a fork of
[`[ring-oauth2 "0.1.4"]`](https://github.com/weavejester/ring-oauth2),
extended and tweaked to support our needs. Feel free to use if you think it's
useful to you, too.


## Installation

To install, add the following to your project `:dependencies`:

[![Clojars Project](https://img.shields.io/clojars/v/gorillalabs/ring-oauth2.svg)](https://clojars.org/gorillalabs/ring-oauth2)

## Usage

The middleware function to use is `ring.middleware.oauth2/wrap-oauth2-flow`.
This takes a Ring handler, a map of profiles, and optional options
as arguments. 

### Profiles

Each profile has a key to identify it, and a map of
properties that define how to authorize against a third-party service.
For an explanation of the options see [_profiles_ documentation](docs/PROFILES.md).

Here's an example that provides authentication with GitHub using
default options:

```clojure
(require '[ring.middleware.oauth2 :refer [wrap-oauth2-flow])

(def handler
  (wrap-oauth2-flow
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

### State Management Strategies

The options to the middleware define which strategy to use to create
and verify state (which secures the communication to the OAuth provider).

By default, ring-oauth uses a _session based state management strategy_: This
will create a random state in the session and compare state from requests
to the session state. In order to be a drop in replacement for the original
`ring-oauth2`, this is our default strategy.

**If using the session-based state management strategy:** Please note, you should
enable cookies to be sent with cross-site requests, in order to make the callback
request handling work correctly, eg:

```clojure
(-> handler
  (wrap-oauth2-flow profiles)
  (wrap-defaults 
    (assoc-in site-defaults [:session :cookie-attrs :same-site] :lax)))
```

### Drop in replacement for `ring-oauth2`

To simplify things, we want you to be able to switch from `ring-oauth2`
to `gorillalabs/ring-oauth2` simply by changing the dependency. Thus,
we provide the wrapper `wrap-oauth2` which comes with the same defaults
as `ring-oauth2`.

## Options

Using the optional options paramter, you can configure the behaviour
of wrap-oauth2.

Using the `:strategy` option, you are able to configure a `state`
management strategy. The `state` is a CSRF-protection mechanism. The
default strategy relies on a server-side session to store the token
used for `state` in order to compare `state` received to the 
session-token. To use another strategy, implement the
`ring.middleware.oauth2.strategy/Strategy`-protocol.

## Workflow diagram

The following image is a workflow diagram that describes the OAuth2
authorization process for Ring-OAuth2. It should give you an overview
of how all the different URIs interact.

![OAuth2 Workflow](docs/workflow.png)


## License

Copyright © 2017 James Reeves

Released under the MIT License.
