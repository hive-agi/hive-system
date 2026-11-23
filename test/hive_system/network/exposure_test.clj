(ns hive-system.network.exposure-test
  "The shared exposure policy (STD-04 T7): examples carried over from
   hive-mcp's exposure tests, and properties for what must never happen."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-system.network.exposure :as exposure]
            [malli.instrument :as mi]))
;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private gen-maybe-str
  (gen/one-of [(gen/return nil) (gen/return "") (gen/return "  ")
               gen/string-alphanumeric gen/string]))

(def ^:private gen-blank
  (gen/elements [nil "" " " "   " "\t" "\n"]))

(def ^:private gen-token
  "A non-blank secret."
  (gen/such-that (complement str/blank?) gen/string-alphanumeric 100))

;; ---------------------------------------------------------------------------
;; Examples: the cases of hive-mcp.transport.exposure-trifecta-test

(deftest bind-host-examples
  (doseq [[secret requested expected] [[nil nil "127.0.0.1"]
                                        [nil "0.0.0.0" "127.0.0.1"]
                                        ["   " "10.0.0.5" "127.0.0.1"]
                                        ["k" nil "0.0.0.0"]
                                        ["k" "" "0.0.0.0"]
                                        ["k" "10.0.0.5" "10.0.0.5"]]]
    (is (= expected (exposure/bind-host secret requested))
        (pr-str [secret requested]))))

(deftest bearer-ok-examples
  (doseq [[secret header expected] [[nil nil true]
                                    ["" "anything" true]
                                    ["tok" "Bearer tok" true]
                                    ["tok" nil false]
                                    ["tok" "Bearer to" false]
                                    ["tok" "Bearer tokk" false]
                                    ["tok" "tok" false]]]
    (is (= expected (exposure/bearer-ok? secret header))
        (pr-str [secret header]))))

;; ---------------------------------------------------------------------------
;; Properties

(defspec no-secret-never-binds-beyond-loopback 300
  (prop/for-all [secret gen-blank
                 requested gen-maybe-str]
    (= "127.0.0.1" (exposure/bind-host secret requested))))

(defspec bind-host-is-never-blank 300
  (prop/for-all [secret gen-maybe-str
                 requested gen-maybe-str]
    (not (str/blank? (exposure/bind-host secret requested)))))

(defspec the-exact-header-is-accepted 300
  (prop/for-all [token gen-token]
    (true? (exposure/bearer-ok? token (str "Bearer " token)))))

(defspec a-prefix-of-the-token-is-refused 300
  (prop/for-all [token gen-token
                 cut gen/nat]
    (let [prefix (subs token 0 (mod cut (count token)))]
      (false? (exposure/bearer-ok? token (str "Bearer " prefix))))))

(defspec a-suffixed-token-is-refused 300
  (prop/for-all [token gen-token
                 extra (gen/not-empty gen/string)]
    (false? (exposure/bearer-ok? token (str "Bearer " token extra)))))

(defspec a-case-variant-of-the-token-is-refused 300
  (prop/for-all [token (gen/such-that #(not= % (str/upper-case %)) gen-token 100)]
    (and (false? (exposure/bearer-ok? token (str "Bearer " (str/upper-case token))))
         (false? (exposure/bearer-ok? token (str "BEARER " token)))
         (false? (exposure/bearer-ok? token (str "bearer " token))))))

(defspec a-missing-or-blank-header-is-refused 300
  (prop/for-all [token gen-token
                 header (gen/elements [nil "" " " "Bearer" "Bearer "])]
    (false? (exposure/bearer-ok? token header))))

(defspec the-bare-token-is-refused 300
  (prop/for-all [token gen-token]
    (false? (exposure/bearer-ok? token token))))

(defspec constant-time=-agrees-with-equality 300
  (prop/for-all [a gen/bytes b gen/bytes]
    (= (exposure/constant-time= a b) (= (seq a) (seq b)))))

;; ---------------------------------------------------------------------------
;; Origin and Host

(deftest loopback-origin-examples
  (testing "loopback origins, any port, http or https"
    (doseq [o ["http://localhost:8280" "http://127.0.0.1" "https://localhost"
               "http://[::1]:9999" "HTTP://LocalHost:1" "http://127.0.0.1:65535"]]
      (is (true? (exposure/loopback-origin? o)) o)))
  (testing "foreign, malformed or opaque origins are refused"
    (doseq [o [nil "" "null" "http://evil.example" "http://localhost.evil.example"
               "http://127.0.0.1.evil.example" "http://evil.example/localhost"
               "http://localhost@evil.example" "http://user@localhost"
               "file://localhost" "ws://localhost" "localhost"
               "http://localhost/" "http://localhost:99999" "http://127.0.0.2"
               "http://[::2]" "http://::1" "http://localhost:80x"]]
      (is (false? (exposure/loopback-origin? o)) (pr-str o)))))

(deftest origin-ok-admits-a-non-browser-client
  (is (true? (exposure/origin-ok? nil)))
  (is (true? (exposure/origin-ok? "http://localhost:8280")))
  (is (false? (exposure/origin-ok? "http://evil.example")))
  (is (false? (exposure/origin-ok? ""))))

(deftest loopback-host-examples
  (doseq [h ["127.0.0.1" "127.0.0.1:7910" "localhost" "LOCALHOST:8080"
             "[::1]" "[::1]:9998" "::1"]]
    (is (true? (exposure/loopback-host? h)) h))
  (doseq [h [nil "" " " "evil.example" "localhost.evil.example"
             "evil.example:127" "127.0.0.1.nip.io" "0.0.0.0" "[::]"
             "localhost:abc" "localhost:70000" "user@localhost" "localhost/x"
             "10.0.0.5:7910"]]
    (is (false? (exposure/loopback-host? h)) (pr-str h))))

(def ^:private gen-port
  (gen/one-of [(gen/return nil) (gen/choose 0 65535)]))

(def ^:private gen-loopback-name
  (gen/elements ["127.0.0.1" "[::1]" "localhost" "LocalHost"]))

(defn- authority [host port]
  (if port (str host ":" port) host))

(defspec every-port-on-a-loopback-name-is-loopback 300
  (prop/for-all [host gen-loopback-name
                 port gen-port
                 scheme (gen/elements ["http" "https"])]
    (and (exposure/loopback-host? (authority host port))
         (exposure/loopback-origin? (str scheme "://" (authority host port))))))

(defspec a-loopback-name-with-a-foreign-suffix-is-not-loopback 300
  (prop/for-all [host gen-loopback-name
                 suffix (gen/fmap #(str "." % ".example")
                                  (gen/not-empty gen/string-alphanumeric))
                 port gen-port]
    (let [a (authority (str host suffix) port)]
      (and (not (exposure/loopback-host? a))
           (not (exposure/loopback-origin? (str "http://" a)))))))

(defspec arbitrary-strings-never-throw 300
  (prop/for-all [s gen/string]
    (and (boolean? (exposure/loopback-host? s))
         (boolean? (exposure/loopback-origin? s))
         (boolean? (exposure/bearer-ok? "tok" s)))))

;; ---------------------------------------------------------------------------
;; Contracts

(deftest the-malli-contracts-hold-under-instrumentation
  (mi/collect! {:ns ['hive-system.network.exposure]})
  (mi/instrument! {:filters [(mi/-filter-ns 'hive-system.network.exposure)]})
  (try
    (is (= "127.0.0.1" (exposure/bind-host nil "0.0.0.0")))
    (is (false? (exposure/bearer-ok? "tok" nil)))
    (is (true? (exposure/loopback-host? "localhost:1")))
    (is (false? (exposure/loopback-origin? nil)))
    (finally
      (mi/unstrument! {:filters [(mi/-filter-ns 'hive-system.network.exposure)]}))))
