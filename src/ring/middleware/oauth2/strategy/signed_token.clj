(ns ring.middleware.oauth2.strategy.signed-token
  (:require [ring.middleware.oauth2.strategy :as strategy :refer [get-access-token authorize-uri]]
            [ring.middleware.oauth2.default-handlers :refer [default-state-mismatch-handler default-success-handler]]
            [ring.middleware.params :as params]
            [buddy.sign.jwt :as jwt]
            [ring.middleware.cookies :as cookies]
            [clj-time.core :as time]
            [ring.util.response :as resp]
            [clojure.tools.logging :as log]
            [crypto.equality])
  (:import (clojure.lang ExceptionInfo)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Managing state using signed tokens
;;
;; This does not require a shared session, if you want to distribute this horizontally
;; No need to encrypt state, as it does not contain secrets. Follows a double cookie pattern/encrypted token pattern.
;; Must not rely on encrypted token alone, as we do not have a user-id to encode. However, signing is enough to ensure
;; issuer identity, no encryption required. Thus, we can operate using asymmetric encryption, using the issuers private
;; key in the state-emitting service (launch-handler) and the issuers public key (which can easily be distributed to any consuming
;; service) in the state-verifying service (redirect-handler).
;;

(def ^:private crypt-options {:alg :rs512
                              :enc :a128cbc-hs256})


(defn sign-state [private-key-of-signing-system expires]
  (->
    {:jti (crypto.random/base64 4096)
     :iat (clj-time.coerce/to-epoch (time/now))             ;; Issued at (see https://tools.ietf.org/html/rfc7519#section-4.1.6)
     :exp (clj-time.coerce/to-epoch (time/plus (time/now) expires)) ;; Expires (see https://tools.ietf.org/html/rfc7519#section-4.1.4)
     }
    (jwt/sign private-key-of-signing-system crypt-options)))




(defn token-name [cookie-opts profile]
  (str (:id-prefix cookie-opts) "_" (name (:id profile))))

(defn cookie-jwt [cookie-opts profile request]
  (let [c-req (cookies/cookies-request request)
        token-cookie (get (:cookies c-req) (token-name cookie-opts profile))]
    (:value token-cookie)))

(defn valid-state? [public-key-of-signing-system request-state cookie-state]
  (try (let [{expires :exp issued-at :iat} (jwt/unsign request-state public-key-of-signing-system crypt-options)]
         ;; signature, exp, iat are checked by unsign anyhow (see buddy.sign.jwt/validate-claims)
         (when-not (crypto.equality/eq? cookie-state request-state)
           (throw (ex-info (str "State does not match ")
                           {:type :validation :cause :equality})))
         true)
       (catch ExceptionInfo e
         (when-not (= (:type (ex-data e)) :validation)
           (throw e))
         (when-not (= (:cause (ex-data e)) :exp)
           (log/warn
             e
             "Security warning: Potential CSRF-Attack"
             (ex-data e)))
         false)))




(deftype SignedTokenSMS [public-key private-key expiration-period cookie-opts]
  strategy/StateManagementStrategy

  (launch-handler [_ profile]
    (-> (fn [request]
          (let [state (sign-state
                        private-key                           ;; the private key of the state-generator used to sign the state
                        expiration-period
                        )]
            (-> (resp/redirect (authorize-uri profile request state))
                (assoc :cookies {(token-name cookie-opts profile)
                                 {:value     state
                                  :secure    true
                                  :http-only true
                                  :domain    (:domain cookie-opts)
                                  :path      (:path cookie-opts)
                                  :max-age   86400            ; - the number of seconds until the cookie expires. 86400s = 24h
                                  :same-site :lax             ;; when set to strict, OAuth login won't work correctly, as the request to "/" is initiated by Github in the first place (Github->oauth-Callback,redirect->/)
                                  }}))))
        (params/wrap-params)
        (cookies/wrap-cookies)))

  (redirect-handler [_ profile]
    (let [error-handler-fn (:state-mismatch-handler profile default-state-mismatch-handler)
          success-handler (:success-handler profile default-success-handler)]
      (-> (fn [request]
            (if (valid-state? public-key
                              (get-in request [:query-params "state"])
                              (cookie-jwt cookie-opts profile request))
              (let [access-token (get-access-token profile request)]
                (-> (success-handler profile access-token request)
                    (assoc :cookies {(token-name cookie-opts profile) {:value     "deleted" ;; this is to overwrite ...
                                                                       :secure    true
                                                                       :http-only true
                                                                       :domain    (:domain cookie-opts)
                                                                       :path      (:path cookie-opts)
                                                                       :max-age   0 ;; ... and remove the cookie (max-age 0 means this cookie won't be sent on future requests)
                                                                       :same-site :lax}})))
              (error-handler-fn profile request)))
          (params/wrap-params)
          (cookies/wrap-cookies))))

  (wrap-request [_ request]
    request))