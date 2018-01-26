# OAuth2 Profiles

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
`Authorization: Basic base64(id:secret)` as recommended by
[the specification](https://tools.ietf.org/html/rfc6749#section-2.3.1).