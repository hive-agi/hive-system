(ns hive-system.xdg-test
  "hive-system.xdg: base-dir under a MapEnv equals the specification table
   for every kind; an env value always beats the fallback; a relative or
   blank value is ignored; app-dir is a plain join; the multimethod covers
   BaseDirKind exactly.

   Runs under `bb test:bb` and under the JVM suite."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-schemas.test :refer [deftrifecta-from-multi]]
            [hive-system.env :as env]
            [hive-system.path :as path]
            [hive-system.xdg :as xdg]
            [hive-test.mutation :as mut]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def kinds [:config :data :state :cache :runtime])

(def home-only {"HOME" "/h"})

(def spec-table
  "kind -> [variable, base-dir with HOME=/h only]: the specification, by hand."
  {:config  ["XDG_CONFIG_HOME" "/h/.config"]
   :data    ["XDG_DATA_HOME" "/h/.local/share"]
   :state   ["XDG_STATE_HOME" "/h/.local/state"]
   :cache   ["XDG_CACHE_HOME" "/h/.cache"]
   :runtime ["XDG_RUNTIME_DIR" nil]})

(deftest base-dir-golden-home-only
  (doseq [[kind [_ expected]] spec-table]
    (is (= expected (xdg/base-dir home-only kind)) (str kind))))

(deftest base-dir-golden-variable-set
  (doseq [[kind [var _]] spec-table]
    (is (= "/v" (xdg/base-dir {"HOME" "/h" var "/v"} kind)) (str kind))))

(deftest spec-data-agrees-with-the-methods
  (doseq [[kind {:keys [var fallback]}] xdg/spec]
    (is (= (first (spec-table kind)) var))
    (is (= (xdg/base-dir home-only kind)
           (when fallback (apply path/join "/h" fallback))))))

(deftest relative-and-blank-values-are-ignored
  (doseq [v ["rel/dir" "" "   " "~/x"]]
    (is (= "/h/.local/share" (xdg/base-dir {"HOME" "/h" "XDG_DATA_HOME" v} :data))
        (pr-str v)))
  (is (= "/v" (xdg/base-dir {"XDG_DATA_HOME" "  /v  "} :data)) "a value is trimmed"))

(deftest no-home-no-fallback
  (doseq [kind kinds]
    (is (nil? (xdg/base-dir {} kind)) (str kind))
    (is (nil? (xdg/base-dir {"HOME" "relative"} kind)) (str kind))))

(deftest app-dir-is-a-plain-join
  (is (= "/h/.local/state/hive-mcp/heapdumps"
         (xdg/app-dir home-only :state "hive-mcp" "heapdumps")))
  (is (= "/d/hive-mcp" (xdg/app-dir {"XDG_DATA_HOME" "/d/"} :data "hive-mcp")))
  (is (nil? (xdg/app-dir home-only :runtime "hive-mcp"))))

(deftest any-env-source-is-accepted
  (is (= "/h/.config" (xdg/base-dir (env/map-env home-only) :config))))

(deftest the-facade-reads-the-env-seam
  (binding [env/*env* (env/map-env {"HOME" "/bound"})]
    (is (= "/bound/.cache" (xdg/current-base-dir :cache)))
    (is (= "/bound/.config/app/x" (xdg/current-app-dir :config "app" "x")))))

(deftrifecta-from-multi base-dir-dispatch xdg/base-dir
  {:args     [:cat [:map-of :string :string] xdg/BaseDirKind]
   :dispatch xdg/BaseDirKind
   :out      [:maybe :string]
   :total?   true})

;;; =============================================================================
;;; Laws
;;; =============================================================================

(def ^:private gen-abs
  (gen/fmap (fn [segs] (apply str (interleave (repeat "/") segs)))
            (gen/not-empty (gen/vector (gen/elements ["a" "b" "x.y" "s_1"]) 1 4))))

(def ^:private gen-env
  (gen/let [home gen-abs
            vals (gen/vector (gen/one-of [gen-abs (gen/elements ["" "rel" "  "])]) 5)
            mask (gen/vector gen/boolean 5)]
    (into {"HOME" home}
          (keep (fn [[kind v on?]] (when on? [(first (spec-table kind)) v])))
          (map vector kinds vals mask))))

(defspec base-dir-under-map-env-equals-the-spec-table 300
  (prop/for-all [e gen-env kind (gen/elements kinds)]
    (let [[var _] (spec-table kind)
          v (get e var)
          fallback (:fallback (xdg/spec kind))
          expected (if (path/absolute? v)
                     v
                     (when fallback (apply path/join (get e "HOME") fallback)))]
      (= expected (xdg/base-dir e kind)))))

(defspec an-env-value-always-beats-the-fallback 300
  (prop/for-all [e gen-env kind (gen/elements kinds) v gen-abs]
    (= v (xdg/base-dir (assoc e (first (spec-table kind)) v) kind))))

(defspec a-base-dir-is-absolute-or-nil 300
  (prop/for-all [e gen-env kind (gen/elements kinds)]
    (let [d (xdg/base-dir e kind)]
      (or (nil? d) (path/absolute? d)))))

;;; =============================================================================
;;; Mutants
;;; =============================================================================

(mut/deftest-mutations resolve-base-mutants-are-caught
  hive-system.xdg/resolve-base
  [["fallback over the variable"
    (fn [e var fallback]
      (let [h (xdg/home e)]
        (or (when (and h (seq fallback)) (apply path/join h fallback))
            (env/present (xdg/source e) var))))]
   ["relative values accepted"
    (fn [e var fallback]
      (or (env/present (xdg/source e) var)
          (when-let [h (and (seq fallback) (xdg/home e))] (apply path/join h fallback))))]
   ["doubled separator"
    (fn [e var fallback]
      (or (env/present (xdg/source e) var)
          (when-let [h (and (seq fallback) (xdg/home e))]
            (apply str h (map (fn [s] (str "//" s)) fallback)))))]]
  (fn []
    (is (= "/v" (xdg/base-dir {"HOME" "/h" "XDG_DATA_HOME" "/v"} :data)))
    (is (= "/h/.local/share" (xdg/base-dir {"HOME" "/h" "XDG_DATA_HOME" "rel"} :data)))
    (is (= "/h/.cache" (xdg/base-dir home-only :cache)))))
