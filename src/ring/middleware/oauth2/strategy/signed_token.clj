(ns ring.middleware.oauth2.strategy.signed-token
  (:require [ring.middleware.oauth2.strategy :as strategy]
            [ring.middleware.params :as params]
            [buddy.sign.jwt :as jwt]
            [ring.middleware.cookies :as cookies]
            [clj-time.core :as time]
            [clj-time.coerce]
            [ring.util.response :as resp]
            [clojure.tools.logging :as log]
            [crypto.equality]
            [crypto.random])
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

(defn sign-state [private-key expires]
  (jwt/sign
    {;; Do not make this too big or it will blow cookie size limit of 4k
     :jti (crypto.random/base64 512)
     ;; Issued at (see https://tools.ietf.org/html/rfc7519#section-4.1.6)
     :iat (clj-time.coerce/to-epoch (time/now))
     ;; Expires (see https://tools.ietf.org/html/rfc7519#section-4.1.4)
     :exp (clj-time.coerce/to-epoch (time/plus (time/now) expires))}
    private-key
    crypt-options))

(defn token-name [cookie-opts profile]
  (str (:id-prefix cookie-opts) "_" (name (:id profile))))

(defn cookie-jwt [cookie-opts profile request]
  (let [c-req (cookies/cookies-request request)
        token-cookie (get (:cookies c-req) (token-name cookie-opts profile))]
    (:value token-cookie)))

(defn- set-cookie [response cookie-opts profile value max-age]
  (update-in response [:cookies]
             assoc
             (token-name cookie-opts profile)
             (merge {:value     value
                     :secure    true
                     :http-only true
                     ; the number of seconds until the cookie expires.
                     ; 86400s = 24h
                     :max-age   max-age
                     ;; when set to strict, OAuth login won't work correctly,
                     ;; as the request to "/" is initiated by Github
                     ;; in the first place (Github->oauth-Callback,redirect->/)
                     :same-site :lax
                     }
                    (remove (fn [[k v]] (nil? v))
                            (select-keys cookie-opts [:domain :path])))))

(deftype SignedTokenStrategy [public-key private-key expiration-period cookie-opts]
  strategy/Strategy

  (get-token [_ _]
    (sign-state private-key expiration-period))

  (write-token [strategy profile request response token]
    (set-cookie response cookie-opts profile token 86400))

  (valid-token? [_ profile request token]
    (try (let [cookie-state (cookie-jwt cookie-opts profile request)]
           ;; signature, exp, iat are checked by unsign anyhow (see buddy.sign.jwt/validate-claims)
           (jwt/unsign token public-key crypt-options)

           (when-not (crypto.equality/eq? cookie-state token)
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

  (remove-token [strategy profile response]
    (set-cookie response cookie-opts profile "deleted" 0)))

(defn signed-token-strategy [public-key private-key expiration-period cookie-opts]
  (->SignedTokenStrategy public-key private-key expiration-period cookie-opts))
