(ns ring.middleware.oauth2.strategy.signed-token-test
  (:require [clojure.test :refer :all]
            [ring.middleware.oauth2.strategy.signed-token :refer :all]
            [buddy.core.keys :as keys]))

;; these are generated using
;;     openssl genrsa -aes256 -out privkey.pem 2048
;; and
;;     openssl rsa -pubout -in privkey.pem -out pubkey.pem
;; (see https://funcool.github.io/buddy-sign/latest/#generate-keypairs)


(def private-key (keys/private-key "dev-resources/certs/privkey.pem" "password"))
(def public-key (keys/public-key "dev-resources/certs/pubkey.pem"))

(def other-private-key (keys/private-key "dev-resources/certs/privkey-other.pem" "other"))

(def period1h (clj-time.core/hours 1))
(def period-1h (clj-time.core/hours -1))

(deftest test-signed-token-validation
  (testing "valid roundtrip"
    (let [token (sign-state private-key period1h)]
      (is (valid-state? public-key token token))
      (is (< (count token) 3000))
      ))
  (testing "invalid: tokens differ"
    (is (not (valid-state? public-key (sign-state private-key period1h) (sign-state private-key period1h)))))
  (testing "invalid: other private key"
    (is (not (valid-state? public-key (sign-state other-private-key period1h) (sign-state other-private-key period1h)))))
  (testing "invalid: expired"
    (is (not (valid-state? public-key (sign-state private-key period-1h) (sign-state private-key period-1h))))))