(ns hive-system.env-test
  "hive-system.env: the IEnvSource port, its MapEnv and SystemEnv adapters,
   and the *env* seam read at call time. Every environment here is a MapEnv
   value bound or passed in; no var is redefined.

   Runs under `bb test:bb` and under the JVM suite."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.properties :as prop]
            [hive-schemas.test :refer [deftrifecta-from-schema]]
            [hive-system.env :as env]
            [malli.core :as m]
            [malli.generator :as mg]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(deftest map-env-is-a-value
  (let [e (env/map-env {"HOME" "/h" "X" ""})]
    (is (= "/h" (env/env-get e "HOME")))
    (is (= "" (env/env-get e "X")))
    (is (nil? (env/env-get e "ABSENT")))
    (is (= {"HOME" "/h" "X" ""} (env/env-map e)))
    (is (= e (env/map-env {"HOME" "/h" "X" ""})) "two MapEnvs over one map are equal")))

(deftest map-env-is-total
  (is (= {} (env/env-map (env/map-env nil))))
  (is (= {"K" "v"} (env/env-map (env/map-env {"K" "v" :k "v" "N" 1 "M" nil})))
      "non-string keys and values are dropped"))

(deftest present-trims-and-drops-blank
  (let [e (env/map-env {"A" "  /x  " "B" "   " "C" ""})]
    (is (= "/x" (env/present e "A")))
    (is (nil? (env/present e "B")))
    (is (nil? (env/present e "C")))
    (is (nil? (env/present e "D")))))

(deftest the-seam-is-read-at-call-time
  (let [read-home (fn [] (env/lookup "HOME"))]
    (binding [env/*env* (env/map-env {"HOME" "/bound"})]
      (is (= "/bound" (read-home)))
      (is (= "/bound" (env/present "HOME")))
      (is (= {"HOME" "/bound"} (env/snapshot))))
    (binding [env/*env* (env/map-env {})]
      (is (nil? (read-home)) "a second binding is honoured by the same closure"))))

(deftest system-env-reads-the-host
  (let [sys (env/->SystemEnv)
        snap (env/env-map sys)]
    (is (map? snap))
    (is (every? string? (keys snap)))
    (is (every? string? (vals snap)))
    (doseq [[k v] (take 5 snap)]
      (is (= v (env/env-get sys k))))
    (is (nil? (env/env-get sys nil)))))

(deftest the-default-seam-is-the-system
  (is (= (env/->SystemEnv) env/*env*)))

(deftrifecta-from-schema map-env-round-trips env/map-env
  {:in       env/EnvMap
   :out      [:fn (fn [e] (satisfies? env/IEnvSource e))]
   :mutation false
   :rel      (fn [m e] (and (= m (env/env-map e))
                            (every? (fn [[k v]] (= v (env/env-get e k))) m)))})

(defspec snapshot-validates-as-an-env-map 100
  (prop/for-all [m (mg/generator env/EnvMap)]
    (m/validate env/EnvMap (env/snapshot (env/map-env m)))))
