(ns hive-system.network.path-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-system.network.path :as np]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(deftest xdg-runtime-dir-wins
  (is (= {:ok {:path "/run/user/1000/hive/mcp-nrepl.sock" :dir "/run/user/1000/hive"}}
         (np/socket-path {"XDG_RUNTIME_DIR" "/run/user/1000"} "/tmp" 1000 "mcp-nrepl")))
  (testing "a trailing slash is not doubled"
    (is (= "/run/user/1000/hive/x.sock"
           (get-in (np/socket-path {"XDG_RUNTIME_DIR" "/run/user/1000/"} "/tmp" 1000 "x")
                   [:ok :path])))))

(deftest tmpdir-fallback-with-uid
  (is (= {:ok {:path "/tmp/hive-1000/universe-u1.sock" :dir "/tmp/hive-1000"}}
         (np/socket-path {} "/tmp/" 1000 "universe" "u1")))
  (testing "a blank XDG_RUNTIME_DIR counts as unset"
    (is (= "/tmp/hive-7/a.sock"
           (get-in (np/socket-path {"XDG_RUNTIME_DIR" " "} "/tmp" 7 "a") [:ok :path]))))
  (testing "no uid and no XDG is refused"
    (is (= :socket-path/no-uid (:error (np/socket-path {} "/tmp" nil "a"))))))

(deftest over-long-path-refused
  (let [res (np/socket-path {} "/tmp" 1000 (apply str (repeat 90 "a")))]
    (is (= :socket-path/too-long (:error res)))
    (is (> (:bytes res) np/max-path-bytes)))
  (testing "multi-byte characters are counted in bytes, not chars"
    ;; 45 x é: 62 chars but 107 bytes
    (let [xdg (str "/r/" (apply str (repeat 45 "é")))
          res (np/socket-path {"XDG_RUNTIME_DIR" xdg} "/tmp" 1 "svc")]
      (is (< (count (str xdg "/hive/svc.sock")) np/max-path-bytes))
      (is (= :socket-path/too-long (:error res))))))

(deftest bad-names-refused
  (is (= :socket-path/bad-service (:error (np/socket-path {} "/tmp" 1 "../etc"))))
  (is (= :socket-path/bad-service (:error (np/socket-path {} "/tmp" 1 nil))))
  (is (= :socket-path/bad-id (:error (np/socket-path {} "/tmp" 1 "svc" "a/b")))))

(def gen-name
  (gen/fmap (fn [[c cs]] (apply str c cs))
            (gen/tuple (gen/elements (seq "abcXYZ019_-"))
                       (gen/vector (gen/elements (seq "abc.XYZ019_-")) 0 40))))

(defspec path-is-bounded-and-shaped 200
  (prop/for-all [xdg   (gen/one-of [(gen/return nil)
                                    (gen/fmap #(str "/run/user/" %) gen/nat)])
                 uid   gen/nat
                 svc   gen-name
                 id    (gen/one-of [(gen/return nil) gen-name])]
    (let [res (np/socket-path (cond-> {} xdg (assoc "XDG_RUNTIME_DIR" xdg)) "/tmp" uid svc id)]
      (if-let [{:keys [path dir]} (:ok res)]
        (and (<= (np/utf8-length path) np/max-path-bytes)
             (str/starts-with? path (str dir "/"))
             (str/ends-with? path (str svc (when id (str "-" id)) ".sock"))
             (if xdg (str/starts-with? dir xdg) (= dir (str "/tmp/hive-" uid))))
        (= :socket-path/too-long (:error res))))))
