(ns ring.middleware.oauth2
  (:require [ring.middleware.oauth2.strategy.session :as session]
            [clj-http.client :as http]
            [clj-time.core :as time]
            [clojure.string :as str]
            [crypto.random :as random]
            [ring.util.codec :as codec]
            [ring.util.request :as req]
            [ring.util.response :as resp]

            [ring.util.codec :as codec]
            [clojure.string :as str]
            [clj-time.core :as time]
            [clj-time.coerce]))

(defn- parse-redirect-url [{:keys [redirect-uri]}]
  (.getPath (java.net.URI. redirect-uri)))


(defn wrap-oauth2 [handler profiles & {:keys [state-management-strategy
                                              access-tokens-to-request?]
                                       :or   {state-management-strategy session/session-sms
                                              access-tokens-to-request? true}}]
  (let [profiles (for [[k v] profiles] (assoc v :id k))
        launches (into {} (map (juxt :launch-uri identity)) profiles)
        redirects (into {} (map (juxt parse-redirect-url identity)) profiles)]
    (fn [{:keys [uri] :as request}]
      (if-let [profile (launches uri)]
        (((:make-launch-handler state-management-strategy) profile) request)
        (if-let [profile (redirects uri)]
          (((:make-redirect-handler state-management-strategy) profile) request)
          (handler (if access-tokens-to-request?
                     (:wrap-request state-management-strategy)
                     request)))))))
