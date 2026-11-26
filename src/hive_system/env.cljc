(ns hive-system.env
  "The process environment as a port.

     (env-get (->MapEnv {\"HOME\" \"/h\"}) \"HOME\")  => \"/h\"
     (lookup \"HOME\")                              => through *env*
     (binding [*env* (map-env {\"HOME\" \"/h\"})] (lookup \"HOME\")) => \"/h\"

   Layout: value objects (malli), the IEnvSource port, two adapters (MapEnv,
   a pure value; SystemEnv, the boundary reading the host), the `*env*` seam
   read at CALL time, a facade over it.

   A caller that needs a different environment binds `*env*` or passes a
   source; nobody redefines a var.

   Requires only clojure.string and malli, so it loads under babashka."
  (:require [clojure.string :as str]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Value objects
;;; =============================================================================

(def EnvKey
  "An environment variable name."
  [:string {:min 1 :gen/schema [:enum "HOME" "XDG_DATA_HOME" "XDG_STATE_HOME"
                                "XDG_CONFIG_HOME" "XDG_CACHE_HOME" "XDG_RUNTIME_DIR" "X"]}])

(def EnvValue
  "An environment variable value."
  [:string {:gen/schema [:enum "" "  " "/h" "/x/y" "rel/dir" "/h/" "v"]}])

(def EnvMap
  "An environment as data: variable name to value."
  [:map-of EnvKey EnvValue])

;;; =============================================================================
;;; Port
;;; =============================================================================

(defprotocol IEnvSource
  "Where environment variables are read from."
  (env-get [this k]
    "The string value of variable K, or nil when it is unset.")
  (env-map [this]
    "Every variable as an EnvMap."))

;;; =============================================================================
;;; Adapters
;;; =============================================================================

(defrecord MapEnv [vars]
  IEnvSource
  (env-get [_ k] (get vars k))
  (env-map [_] vars))

(defn map-env
  "A MapEnv over the EnvMap M. A nil M is the empty environment; entries whose
   key or value is not a string are dropped."
  [m]
  (->MapEnv (into {} (filter (fn [[k v]] (and (string? k) (string? v)))) m)))

(defrecord SystemEnv []
  IEnvSource
  (env-get [_ k]
    #?(:clj  (when (string? k) (System/getenv ^String k))
       :cljs (when (and (string? k) (exists? js/process))
               (aget (.-env js/process) k))))
  (env-map [_]
    #?(:clj  (into {} (System/getenv))
       :cljs (if (exists? js/process)
               (js->clj (.-env js/process))
               {}))))

(def ^:dynamic *env*
  "The source the facade reads. Read at CALL time; bind a MapEnv to supply an
   environment without touching the host."
  (->SystemEnv))

;;; =============================================================================
;;; Facade
;;; =============================================================================

(defn lookup
  "The value of K in SOURCE (default `*env*`), or nil when unset."
  ([k] (lookup *env* k))
  ([source k] (env-get source k)))

(defn present
  "The trimmed value of K in SOURCE (default `*env*`) when it is a non-blank
   string, else nil."
  ([k] (present *env* k))
  ([source k]
   (let [v (env-get source k)]
     (when (and (string? v) (not (str/blank? v)))
       (str/trim v)))))

(defn snapshot
  "Every variable of SOURCE (default `*env*`) as an EnvMap."
  ([] (snapshot *env*))
  ([source] (env-map source)))

;;; =============================================================================
;;; Contracts
;;; =============================================================================

(m/=> map-env [:=> [:cat [:maybe [:map-of :any :any]]] [:fn (fn [e] (instance? MapEnv e))]])
