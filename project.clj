(defproject gorillalabs/ring-oauth2 "0.0.0"
  :description "OAuth 2.0 client middleware for Ring"
  :url "https://github.com/weavejester/ring-oauth2"
  :license {:name "The MIT License"
            :url  "http://opensource.org/licenses/MIT"}
  :middleware [leiningen.v/dependency-version-from-scm
               leiningen.v/version-from-scm
               leiningen.v/add-workspace-data]
  :plugins [[com.roomkey/lein-v "6.2.0"]]
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [cheshire "5.8.0"]
                 [clj-http "3.7.0"]
                 [clj-time "0.14.2"]
                 [ring/ring-core "1.6.3"]
                 [crypto-random "1.2.0"]
                 [buddy/buddy-core "1.4.0"]
                 [buddy/buddy-sign "2.2.0"]]
  :profiles {:dev {:dependencies [[clj-http-fake "1.0.3"]
                                  [ring/ring-mock "0.3.1"]]}}

  :vcs :git
  :scm {:name "git"
        :url  "https://github.com/gorillalabs/ring-oauth2"}

  :deploy-repositories [["releases" :clojars]]
  :release-tasks [["vcs" "assert-committed"]
                  ["v" "update"]                            ;; compute new version & tag it
                  ["deploy"]
                  ["vcs" "push"]])