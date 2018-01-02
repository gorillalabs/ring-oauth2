(ns ring.middleware.oauth2
  (:require [clj-http.client :as http]
            [clj-time.core :as time]
            [clojure.string :as str]
            [crypto.random :as random]
            [ring.util.codec :as codec]
            [ring.util.request :as req]
            [ring.util.response :as resp]

            [ring.middleware.params :as params]
            [buddy.sign.jwt :as jwt]
            [ring.middleware.cookies :as cookies]
            ))

(defn- redirect-uri [profile request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri profile))
      str))

(defn- scopes [profile]
  (str/join " " (map name (:scopes profile))))

(defn- authorize-uri [profile request state]
  (str (:authorize-uri profile)
       (if (.contains ^String (:authorize-uri profile) "?") "&" "?")
       (codec/form-encode {:response_type "code"
                           :client_id     (:client-id profile)
                           :redirect_uri  (redirect-uri profile request)
                           :scope         (scopes profile)
                           :state         state})))

(defn- random-state []
  (-> (random/base64 9) (str/replace "+" "-") (str/replace "/" "_")))

(defn encrypt-state [profile]
  (jwt/encrypt {:state (random-state)
                :nonce (crypto.random/base64 256)}
               (:public-key profile) {:alg :rsa-oaep-256}))

;; Session-state
#_(defn- make-launch-handler [profile]
  (fn [{:keys [session] :or {session {}} :as request}]
    (let [state (random-state)]
      (-> (resp/redirect (authorize-uri profile request state))
          (assoc :session (assoc session ::state state))))))


;; Session-state
#_(defn- state-matches? [request]
  (= (get-in request [:session ::state])
     (get-in request [:query-params "state"])))


(defn- make-launch-handler [profile]
       (fn [request]
           (let [state (encrypt-state profile)]
                (resp/redirect (authorize-uri profile request state)))))

(defn- state-matches? [profile request]
       (let [state (get-in request [:query-params "state"])]
            (try (jwt/decrypt state (:private-key profile) {:alg :rsa-oaep-256})
                 (catch Exception e
                   (if (= (ex-data e) {:type :validation :cause :signature})
                     false
                     (throw e))))))


(defn- format-access-token
  [{{:keys [access_token expires_in refresh_token id_token]} :body :as r}]
  (-> {:token access_token}
      (cond-> expires_in (assoc :expires (-> expires_in time/seconds time/from-now))
              refresh_token (assoc :refresh-token refresh_token)
              id_token (assoc :id-token id_token))))

(defn- request-params [profile request]
  {:grant_type    "authorization_code"
   :code          (get-in request [:query-params "code"])
   :redirect_uri  (redirect-uri profile request)})

(defn- add-header-credentials [opts id secret]
  (assoc opts :basic-auth [id secret]))

(defn- add-form-credentials [opts id secret]
  (assoc opts :form-params (-> (:form-params opts)
                               (merge {:client_id     id
                                       :client_secret secret}))))

(defn- get-access-token
  [{:keys [access-token-uri client-id client-secret basic-auth?]
    :or {basic-auth? false} :as profile} request]
  (format-access-token
   (http/post access-token-uri
     (cond-> {:accept :json, :as  :json,
              :form-params (request-params profile request)}
       basic-auth? (add-header-credentials client-id client-secret)
       (not basic-auth?) (add-form-credentials client-id client-secret)))))

(defn default-state-mismatch-handler [_ _]
  {:status 400, :headers {}, :body "State mismatch"})

(defn default-success-handler [{:keys [id landing-uri] :as profile}
                               access-token
                               {:keys [session] :or {session {}} :as request}]
      (-> (resp/redirect landing-uri)
          (assoc :session (-> session
                              (assoc-in [::access-tokens id] access-token)))))


#_(defn- make-redirect-handler [{:keys [id landing-uri] :as profile}]
  (let [error-handler (:state-mismatch-handler profile state-mismatch-handler)]
    (fn [{:keys [session] :or {session {}} :as request}]
      (if (state-matches? request)
        (let [access-token (get-access-token profile request)]
          (-> (resp/redirect landing-uri)
              (assoc :session (-> session
                                  (assoc-in [::access-tokens id] access-token)
                                  (dissoc ::state)))))
        (error-handler request)))))

(defn- make-redirect-handler [profile]
       (let [error-handler-fn (:state-mismatch-handler profile default-state-mismatch-handler)
             success-handler (:success-handler profile default-success-handler)]
            (-> (fn [request]
                    (if (state-matches? profile request)
                      (let [access-token (get-access-token profile request)]
                           (success-handler profile access-token request))
                      (error-handler-fn profile request)))
                (params/wrap-params)
                (cookies/wrap-cookies))))

#_(defn- assoc-access-tokens [request]
  (if-let [tokens (-> request :session ::access-tokens)]
    (assoc request :oauth2/access-tokens tokens)
    request))

(defn- parse-redirect-url [{:keys [redirect-uri]}]
  (.getPath (java.net.URI. redirect-uri)))

(defn wrap-oauth2 [handler profiles]
  (let [profiles  (for [[k v] profiles] (assoc v :id k))
        launches  (into {} (map (juxt :launch-uri identity)) profiles)
        redirects (into {} (map (juxt parse-redirect-url identity)) profiles)]
    (fn [{:keys [uri] :as request}]
      (if-let [profile (launches uri)]
        ((make-launch-handler profile) request)
        (if-let [profile (redirects uri)]
          ((make-redirect-handler profile) request)
          (handler request #_(assoc-access-tokens request)))))))
