(ns ring.middleware.signed-token-test
  (:require [clj-http.fake :as fake]
            [clj-time.core :as time]
            [clojure.string :as str]
            [clojure.test :refer :all]
            [ring.middleware.oauth2 :as oauth2 :refer [wrap-oauth2-flow]]
            [ring.middleware.oauth2.strategy.signed-token :as signed-token :refer [sign-state]]
            [ring.mock.request :as mock]
            [ring.middleware.params :refer [wrap-params]]
            [ring.util.codec :as codec]
            [buddy.core.keys :as keys]))


;; these are generated using
;;     openssl genrsa -aes256 -out privkey.pem 2048
;; and
;;     openssl rsa -pubout -in privkey.pem -out pubkey.pem
;; (see https://funcool.github.io/buddy-sign/latest/#generate-keypairs)


(def private-key (keys/private-key "dev-resources/certs/privkey.pem" "password"))
(def public-key (keys/public-key "dev-resources/certs/pubkey.pem"))
(def period1h (clj-time.core/hours 1))

(def cookie-opts {:id-prefix "state"
                  :domain    ".mywebservice.local"
                  :path      "/"})

(def my-signed-token-strategy (signed-token/signed-token-strategy public-key private-key period1h cookie-opts))

(def test-profile
  {:authorize-uri    "https://example.com/oauth2/authorize"
   :access-token-uri "https://example.com/oauth2/access-token"
   :redirect-uri     "/oauth2/test/callback"
   :launch-uri       "/oauth2/test"
   :landing-uri      "/"
   :scopes           [:user :project]
   :client-id        "abcdef"
   :client-secret    "01234567890abcdef"})

(defn- token-handler [req]
  {:status 200, :headers {}, :body {:test {:expires 3600
                                           :token   "defdef"}}})

(def test-handler
  (wrap-oauth2-flow token-handler
                        {:test test-profile}
                        :strategy my-signed-token-strategy
                        :access-token-to-session? false))

(deftest test-launch-uri-encrypted-token
  (let [response (test-handler (mock/request :get "/oauth2/test"))
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


(def token-response
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    "{\"access_token\":\"defdef\",\"expires_in\":3600}"})


(defn- callback [state & [cookie-state]]
  (-> (mock/request :get "/oauth2/test/callback")
      (assoc :query-params {"code" "abcabc", "state" state})
      (update-in [:cookies] assoc "state_test" {:value (or cookie-state state)})))

(deftest test-redirect-uri-encrypted-token
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly token-response)}

    (testing "valid state"
      (let [request (callback (sign-state private-key period1h))
            response (test-handler request)
            expires (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))))

    (testing "sessionless"
      (let [request (callback (sign-state private-key period1h))
            response (test-handler request)
            expires (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= nil (:session response)))))

    (testing "invalid state"
      (let [request (callback "xyzxya")
            response (test-handler request)]
        (is (= {:status 400, :headers {}, :body "State mismatch"}
               response))))

    (testing "non-matching state"
      (let [request (callback (sign-state private-key period1h) (sign-state private-key period1h))
            response (test-handler request)]
        (is (= {:status 400, :headers {}, :body "State mismatch"}
               response))))

    (testing "custom error"
      (let [error {:status 400, :headers {}, :body "Error!"}
            profile (assoc test-profile :state-mismatch-handler (constantly error))
            handler (wrap-oauth2-flow token-handler {:test profile} :strategy my-signed-token-strategy)
            request (callback "xyzxya")
            response (handler request)]
        (is (= {:status 400, :headers {}, :body "Error!"}
               response))))

    (testing "absolute redirect uri"
      (let [profile (assoc test-profile
                      :redirect-uri
                      "https://example.com/oauth2/test/callback?query")
            handler (wrap-oauth2-flow token-handler {:test profile} :strategy my-signed-token-strategy)
            request (callback (sign-state private-key period1h))
            response (handler request)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))))))

(def openid-response
  {:status  200
   :headers {"Content-Type" "application/json"}
   :body    "{\"access_token\":\"defdef\",\"expires_in\":3600,
              \"refresh_token\":\"ghighi\",\"id_token\":\"abc.def.ghi\"}"})

(deftest test-openid-response-encrypted-token
  (fake/with-fake-routes
    {"https://example.com/oauth2/access-token" (constantly openid-response)}

    (testing "valid state"
      (let [request (callback (sign-state private-key period1h))
            response (test-handler request)
            expires (-> 3600 time/seconds time/from-now)]
        (is (= 302 (:status response)))
        (is (= "/" (get-in response [:headers "Location"])))))))