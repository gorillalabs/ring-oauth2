(ns ring.middleware.oauth2.strategy.signed-token
  (:require [ring.middleware.oauth2.strategy :refer [get-access-token authorize-uri]]
            [ring.middleware.oauth2.default-handlers :refer [default-state-mismatch-handler default-success-handler]]
            [ring.middleware.params :as params]
            [buddy.sign.jwt :as jwt]
            [ring.middleware.cookies :as cookies]
            [clj-time.core :as time]
            [ring.util.response :as resp]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Managing state using signed tokens
;;
;; This does not require a shared session, if you want to distribute this horizontally
;; No need to encrypt state, as it does not contain secrets.

(def ^:private crypt-options {:alg :rs512
                              :enc :a128cbc-hs256})


(defn sign-state [private-key-of-signing-system expires]
  (->
    {:jti (crypto.random/base64 4096)                       ;; the nonce is to secure encryption (i.e. to prevent replay attacks). Used as JWT ID in the JWT (see https://tools.ietf.org/html/rfc7519#section-4.1.7).
     :iat (clj-time.coerce/to-long (time/now))              ;; Issued at (see https://tools.ietf.org/html/rfc7519#section-4.1.6)
     :exp (clj-time.coerce/to-long (time/plus (time/now) expires)) ;; Expires (see https://tools.ietf.org/html/rfc7519#section-4.1.4)
     }
    (jwt/sign private-key-of-signing-system crypt-options)))

(defn valid-state? [public-key-of-signing-system state]
  (try (let [{expires :exp issued-at :iat}
             (jwt/unsign state public-key-of-signing-system crypt-options)]
         (and
           (time/after? (time/now)
                        (clj-time.coerce/from-long issued-at))
           (time/before? (time/now)
                         (clj-time.coerce/from-long expires))))
       (catch Exception e
         (if (= (ex-data e) {:type :validation :cause :signature})
           false
           (throw e)))))


(defn- make-redirect-handler [public-key profile]
  (let [error-handler-fn (:state-mismatch-handler profile default-state-mismatch-handler)
        success-handler (:success-handler profile default-success-handler)]
    (-> (fn [request]
          (if (valid-state? public-key (get-in request [:query-params "state"]))
            (let [access-token (get-access-token profile request)]
              (success-handler profile access-token request))
            (error-handler-fn profile request)))
        (params/wrap-params)
        (cookies/wrap-cookies))))

(defn- make-launch-handler [private-key expiration-period profile]
  (fn [request]
    (let [state (sign-state
                  private-key                               ;; the private key of the state-generator used to sign the state
                  expiration-period
                  )]
      (resp/redirect (authorize-uri profile request state)))))

(defn signed-token-sms [public-key private-key expiration-period] ;; (clj-time.core/hours 1)
  {:wrap-request          identity                          ;; TODO: encrypted-token could also embed access tokens.
   :make-redirect-handler (partial make-redirect-handler public-key)
   :make-launch-handler   (partial make-launch-handler private-key expiration-period)})