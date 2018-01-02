(ns ring.middleware.oauth2-test
  (:require [clj-http.fake :as fake]
            [clj-time.core :as time]
            [clojure.string :as str]
            [clojure.test :refer :all]
            [ring.middleware.oauth2 :as oauth2 :refer [wrap-oauth2]]
            [ring.middleware.oauth2.strategy.signed-token :refer [signed-token-sms sign-state]]
            [ring.mock.request :as mock]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.codec :as codec]

            [buddy.core.keys :as keys]

            [ring.middleware.oauth2.strategy.signed-token :refer [signed-token-sms]]
            [ring.middleware.oauth2.strategy.session :refer [session-sms]]
            ))


;; these are generated using
;;     openssl genrsa -aes256 -out privkey.pem 2048
;; and
;;     openssl rsa -pubout -in privkey.pem -out pubkey.pem
;; (see https://funcool.github.io/buddy-sign/latest/#generate-keypairs)


(def private-key (keys/private-key "dev-resources/certs/privkey.pem" "password"))
(def public-key (keys/public-key "dev-resources/certs/pubkey.pem"))
(def period1h (clj-time.core/hours 1))


(def test-profile
  {:authorize-uri    "https://example.com/oauth2/authorize"
   :access-token-uri "https://example.com/oauth2/access-token"
   :redirect-uri     "/oauth2/test/callback"
   :launch-uri       "/oauth2/test"
   :landing-uri      "/"
   :scopes           [:user :project]
   :client-id        "abcdef"
   :client-secret    "01234567890abcdef"

   :public-key       public-key
   :private-key      private-key                            ;; TODO: I dislike having a private key being accessible that easy...
   })



(defn token-handler [req]
  {:status 200, :headers {}, :body {:test {:expires 3600
                                           :token   "defdef"}}})

(def test-handler-session
  (wrap-oauth2 token-handler {:test test-profile}))

(def test-handler-encrypted-token
  (wrap-oauth2 token-handler {:test test-profile} :state-management-strategy signed-token-sms))

(deftest test-launch-uri-session
  (let [response (test-handler-session (mock/request :get "/oauth2/test"))
        location (get-in response [:headers "Location"])
        [_ query] (str/split location #"\?" 2)
        params (codec/form-decode query)]
    (is (= 302 (:status response)))
    (is (.startsWith ^String location "https://example.com/oauth2/authorize?"))
    (is (= {"response_type" "code"
            "client_id"     "abcdef"
            "redirect_uri"  "http://localhost/oauth2/test/callback"
            "scope"         "user project"}
           (dissoc params "state")))
    (is (re-matches #"[A-Za-z0-9_-]{12}" (params "state")))
    (is (= {::oauth2/state (params "state")}
           (:session response)))))

(deftest test-launch-uri-encrypted-token
  (let [response (test-handler-encrypted-token (mock/request :get "/oauth2/test"))
        location (get-in response [:headers "Location"])
        [_ query] (str/split location #"\?" 2)
        params (codec/form-decode query)]
    (is (= 302 (:status response)))
    (is (.startsWith ^String location "https://example.com/oauth2/authorize?"))
    (is (= {"response_type" "code"
            "client_id"     "abcdef"
            "redirect_uri"  "http://localhost/oauth2/test/callback"
            "scope"         "user project"}
           (dissoc params "state")))
    ;; session-less
    (is (= nil (:session response)))))


(deftest test-location-uri-with-query
  (let [profile (assoc test-profile
                  :authorize-uri
                  "https://example.com/oauth2/authorize?business_partner_id=XXXX")
        handler (wrap-oauth2 token-handler {:test profile})
        response (handler (mock/request :get "/oauth2/test"))
        location (get-in response [:headers "Location"])]
    (is (.startsWith ^String location "https://example.com/oauth2/authorize?business_partner_id=XXXX&"))))

(def token-response
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    "{\"access_token\":\"defdef\",\"expires_in\":3600}"})

(defn approx-eq [a b]
  (time/within?
    (time/interval (time/minus a (time/seconds 1)) (time/plus a (time/seconds 1)))
    b))

(defn callback [state]
  (-> (mock/request :get "/oauth2/test/callback")
      (assoc :query-params {"code" "abcabc", "state" state})))

(defn callback-session [state session-state]
  (-> (callback state)
      (assoc :session {::oauth2/state session-state})))



(deftest test-redirect-uri-session
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly token-response)}

    (testing "valid state"
      (let [request (callback-session "xyzxyz" "xyzxyz")
            response (test-handler-session request)
            expires (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens))) ;; default success handler is writing access-token to session.
        (is (= "defdef" (-> response :session ::oauth2/access-tokens :test :token)))
        (is (approx-eq (-> 3600 time/seconds time/from-now)
                       (-> response :session ::oauth2/access-tokens :test :expires)))))

    (testing "invalid state"
      (let [request (callback-session "xyzxya" "xyzxyz")
            response (test-handler-session request)]
        (is (= {:status 400, :headers {}, :body "State mismatch"}
               response))))

    (testing "custom error"
      (let [error {:status 400, :headers {}, :body "Error!"}
            profile (assoc test-profile :state-mismatch-handler (constantly error))
            handler (wrap-oauth2 token-handler {:test profile})
            request (callback-session "xyzxya" "xyzxyz")
            response (handler request)]
        (is (= {:status 400, :headers {}, :body "Error!"}
               response))))

    (testing "absolute redirect uri"
      (let [profile (assoc test-profile
                      :redirect-uri
                      "https://example.com/oauth2/test/callback?query")
            handler (wrap-oauth2 token-handler {:test profile})
            request (callback-session "xyzxyz" "xyzxyz")
            response (handler request)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef" (-> response :session ::oauth2/access-tokens :test :token)))
        (is (approx-eq (-> 3600 time/seconds time/from-now)
                       (-> response :session ::oauth2/access-tokens :test :expires)))))))



(deftest test-redirect-uri-encrypted-token
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly token-response)}

    (testing "valid state"
      (let [request (callback (sign-state private-key period1h))
            response (test-handler-encrypted-token request)
            expires (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))))

    (testing "invalid state"
      (let [request (callback "xyzxya")
            response (test-handler-encrypted-token request)]
        (is (= {:status 400, :headers {}, :body "State mismatch"}
               response))))

    (testing "custom error"
      (let [error {:status 400, :headers {}, :body "Error!"}
            profile (assoc test-profile :state-mismatch-handler (constantly error))
            handler (wrap-oauth2 token-handler {:test profile} :state-management-strategy signed-token-sms)
            request (callback "xyzxya")
            response (handler request)]
        (is (= {:status 400, :headers {}, :body "Error!"}
               response))))

    (testing "absolute redirect uri"
      (let [profile (assoc test-profile
                      :redirect-uri
                      "https://example.com/oauth2/test/callback?query")
            handler (wrap-oauth2 token-handler {:test profile} :state-management-strategy signed-token-sms)
            request (callback (sign-state private-key period1h))
            response (handler request)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))))))

(deftest test-access-tokens-key
  (let [tokens {:test {:token "defdef", :expires 3600}}]
    (is (= {:status 200, :headers {}, :body tokens}
           (test-handler-session (-> (mock/request :get "/")
                                     (assoc :session {::oauth2/access-tokens tokens})))))))

(deftest test-true-basic-auth-param
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (fn [req]
       (let [auth (get-in req [:headers "authorization"])]
         (is (and (not (str/blank? auth))
                  (.startsWith auth "Basic")))
         token-response))}

    (testing "valid state"
      (let [profile (assoc test-profile :basic-auth? true)
            handler (wrap-oauth2 token-handler {:test profile})
            request (callback-session "xyzxyz" "xyzxyz")
            response (handler request)]))))

(defn contains-many? [m & ks]
  (every? #(contains? m %) ks))

(deftest test-false-basic-auth-param
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token"
     (wrap-params (fn [req]
                    (let [params (get-in req [:params])]
                      (is (contains-many? params "client_id" "client_secret"))
                      token-response)))}

    (testing "valid state"
      (let [profile (assoc test-profile :basic-auth? false)
            handler (wrap-oauth2 token-handler {:test profile})
            request (callback-session "xyzxyz" "xyzxyz")
            response (handler request)]))))


(def openid-response
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    "{\"access_token\":\"defdef\",\"expires_in\":3600,
              \"refresh_token\":\"ghighi\",\"id_token\":\"abc.def.ghi\"}"})

(deftest test-openid-response-session
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly openid-response)}

    (testing "valid state"
      (let [request (callback-session "xyzxyz" "xyzxyz")
            response (test-handler-session request)
            expires (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))
        (is (map? (-> response :session ::oauth2/access-tokens)))
        (is (= "defdef" (-> response :session ::oauth2/access-tokens :test :token)))
        (is (= "ghighi" (-> response :session ::oauth2/access-tokens
                            :test :refresh-token)))
        (is (= "abc.def.ghi" (-> response :session ::oauth2/access-tokens
                                 :test :id-token)))
        (is (approx-eq (-> 3600 time/seconds time/from-now)
                       (-> response :session ::oauth2/access-tokens :test :expires)))))))

(deftest test-openid-response-encrypted-token
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly openid-response)}

    (testing "valid state"
      (let [request (callback (sign-state private-key period1h))
            response (test-handler-encrypted-token request)
            expires (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))))))