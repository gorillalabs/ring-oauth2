(ns ring.middleware.oauth2.strategy
  "Helper functions to implement strategies."
  (:require [clj-http.client :as http]
            [clj-time.core :as time]
            [clojure.string :as str]
            [ring.util.request :as req]
            [ring.util.codec :as codec]))


(defn- redirect-uri [profile request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri profile))
      str))

(defn- scopes [profile]
  (str/join " " (map name (:scopes profile))))

(defn authorize-uri [profile request state]
  (str (:authorize-uri profile)
       (if (.contains ^String (:authorize-uri profile) "?") "&" "?")
       (codec/form-encode {:response_type "code"
                           :client_id     (:client-id profile)
                           :redirect_uri  (redirect-uri profile request)
                           :scope         (scopes profile)
                           :state         state})))


(defn- format-access-token
  [{{:keys [access_token expires_in refresh_token id_token]} :body :as r}]
  (-> {:token access_token}
      (cond-> expires_in (assoc :expires (-> expires_in time/seconds time/from-now))
              refresh_token (assoc :refresh-token refresh_token)
              id_token (assoc :id-token id_token))))

(defn- request-params [profile request]
  {:grant_type   "authorization_code"
   :code         (get-in request [:query-params "code"])
   :redirect_uri (redirect-uri profile request)})

(defn- add-header-credentials [opts id secret]
  (assoc opts :basic-auth [id secret]))

(defn- add-form-credentials [opts id secret]
  (assoc opts :form-params (-> (:form-params opts)
                               (merge {:client_id     id
                                       :client_secret secret}))))



(defn get-access-token
  [{:keys [access-token-uri client-id client-secret basic-auth?]
    :or   {basic-auth? false} :as profile} request]
  (format-access-token
    (http/post access-token-uri
               (cond-> {:accept      :json, :as :json,
                        :form-params (request-params profile request)}
                       basic-auth? (add-header-credentials client-id client-secret)
                       (not basic-auth?) (add-form-credentials client-id client-secret)))))



(defprotocol StateManagementStrategy

  (launch-handler [this profile]
    "Creates a handler to start an OAuth workflow. Typically, this will redirect to the OAuth provider with the state
    parameter set.")

  (redirect-handler [this profile]
    "Creates a handler to finish the OAuth workflow, i.e. to recieve the redirect from the OAuth provider.
    Needs to make sure state (set by the launch handler) is validated to prevent CSRF attacks. Handles redirects
    by delegation to either success-handler or error-handler from profile.")

  (wrap-request [this request]

    "Wrapper on 'regular' requests (i.e. not one of the middleware-provided launch/redirect/sucess/error-handlers).
    You could use them to transfer access tokens from some internal representation to an entry in the request map.
    If you choose to do so, please use `:ring.middleware.oauth2/access-tokens`.")

  )