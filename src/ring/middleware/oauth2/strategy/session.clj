(ns ring.middleware.oauth2.strategy.session
  (:require [ring.middleware.oauth2.strategy :refer [get-access-token authorize-uri]]
            [ring.middleware.oauth2.default-handlers :refer [default-state-mismatch-handler default-success-handler]]
            [ring.util.response :as resp]
            [clojure.string :as str]
            [crypto.random :as random]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Managing state using sessions
;;
;; This requires a session (or a shared session, can easily be distributed horizontally

(defn access-token-to-session
  [{:keys [id landing-uri] :as profile}
   access-token
   {:keys [session] :or {session {}} :as request}]
  (-> (default-success-handler profile access-token request)
      (assoc :session (-> session
                          (assoc-in [::ring.middleware.oauth2/access-tokens id] access-token)))))




(defn- random-state []
  (-> (random/base64 9) (str/replace "+" "-") (str/replace "/" "_")))

(defn- assoc-access-tokens [request]
  (if-let [tokens (-> request :session ::access-tokens)]
    (assoc request ::ring.middleware.oauth2/access-tokens tokens)
    request))

(defn- valid-state? [request]
  (= (get-in request [:session ::ring.middleware.oauth2/state])
     (get-in request [:query-params "state"])))

(defn- make-redirect-handler [{:keys [id landing-uri] :as profile}]
  (let [error-handler-fn (:state-mismatch-handler profile default-state-mismatch-handler)
        success-handler (:success-handler profile access-token-to-session)]
    (fn [request]
      (if (valid-state? request)
        (let [access-token (get-access-token profile request)]
          (-> (success-handler profile access-token request)
              (update-in [:session] dissoc ::ring.middleware.oauth2/state)))
        (error-handler-fn profile request)))))

(defn- make-launch-handler [profile]
  (fn [{:keys [session] :or {session {}} :as request}]
    (let [state (random-state)]
      (-> (resp/redirect (authorize-uri profile request state))
          (assoc :session (assoc session ::ring.middleware.oauth2/state state))))))

(def session-sms
  {:wrap-request          assoc-access-tokens
   :make-redirect-handler make-redirect-handler
   :make-launch-handler   make-launch-handler})


