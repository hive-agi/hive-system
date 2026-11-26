(ns hive-system.xdg
  "The XDG Base Directory specification, pure over an environment.

     (base-dir {\"HOME\" \"/h\"} :data)                     => \"/h/.local/share\"
     (base-dir {\"XDG_DATA_HOME\" \"/d\" \"HOME\" \"/h\"} :data) => \"/d\"
     (app-dir {\"HOME\" \"/h\"} :state \"hive-mcp\" \"logs\")   => \"/h/.local/state/hive-mcp/logs\"
     (current-base-dir :config)                          => through hive-system.env/*env*

   `spec` is the specification as data. `base-dir` is a multimethod over
   BaseDirKind; each method names its variable and its HOME-relative
   fallback. An ENV argument is an EnvMap or any IEnvSource.

   Rules every method follows: a variable that is set, non-blank and absolute
   wins; a relative one is ignored, as the specification requires; otherwise
   the fallback joins onto HOME when HOME is absolute; otherwise nil.
   `:runtime` has no fallback.

   Requires only malli and the two sibling namespaces, so it loads under
   babashka."
  (:require [hive-system.env :as env]
            [hive-system.path :as path]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Value objects
;;; =============================================================================

(def BaseDirKind
  "The base directories the specification defines."
  [:enum :config :data :state :cache :runtime])

(def AbsPath
  "An absolute path string."
  [:and :string [:fn {:error/message "must be absolute"} path/absolute?]])

(def EnvLike
  "An environment: an EnvMap, or a value implementing IEnvSource."
  [:or env/EnvMap [:fn (fn [x] (satisfies? env/IEnvSource x))]])

(def spec
  "kind -> {:var name :fallback [segment ...] | nil}: the specification as data."
  {:config  {:var "XDG_CONFIG_HOME" :fallback [".config"]}
   :data    {:var "XDG_DATA_HOME"   :fallback [".local" "share"]}
   :state   {:var "XDG_STATE_HOME"  :fallback [".local" "state"]}
   :cache   {:var "XDG_CACHE_HOME"  :fallback [".cache"]}
   :runtime {:var "XDG_RUNTIME_DIR" :fallback nil}})

;;; =============================================================================
;;; Pure core
;;; =============================================================================

(defn source
  "ENV as an IEnvSource: itself when it implements the port, else a MapEnv."
  [env]
  (if (satisfies? env/IEnvSource env) env (env/map-env env)))

(defn- absolute-present
  "The trimmed value of K in SRC when it is non-blank and absolute, else nil."
  [src k]
  (let [v (env/present src k)]
    (when (path/absolute? v) v)))

(defn home
  "HOME in ENV when it is set and absolute, else nil."
  [env]
  (absolute-present (source env) "HOME"))

(defn resolve-base
  "The base directory variable VAR names in ENV, else FALLBACK under HOME,
   else nil. A nil FALLBACK means the directory has none."
  [env var fallback]
  (let [src (source env)]
    (or (absolute-present src var)
        (when-let [h (and (seq fallback) (absolute-present src "HOME"))]
          (apply path/join h fallback)))))

(defmulti base-dir
  "The absolute base directory of KIND in ENV, or nil when the environment
   cannot name one."
  (fn [_env kind] kind))

(defmethod base-dir :config [env _]
  (resolve-base env "XDG_CONFIG_HOME" [".config"]))

(defmethod base-dir :data [env _]
  (resolve-base env "XDG_DATA_HOME" [".local" "share"]))

(defmethod base-dir :state [env _]
  (resolve-base env "XDG_STATE_HOME" [".local" "state"]))

(defmethod base-dir :cache [env _]
  (resolve-base env "XDG_CACHE_HOME" [".cache"]))

(defmethod base-dir :runtime [env _]
  (resolve-base env "XDG_RUNTIME_DIR" nil))

(defn app-dir
  "APP's directory, then SEGS, under the base directory of KIND in ENV, by
   plain join; nil when that base directory is."
  [env kind app & segs]
  (when-let [base (base-dir env kind)]
    (apply path/join base app segs)))

;;; =============================================================================
;;; Facade: the environment of `hive-system.env/*env*`
;;; =============================================================================

(defn current-base-dir
  "`base-dir` of KIND in `hive-system.env/*env*`."
  [kind]
  (base-dir env/*env* kind))

(defn current-app-dir
  "`app-dir` of KIND, APP and SEGS in `hive-system.env/*env*`."
  [kind app & segs]
  (apply app-dir env/*env* kind app segs))

;;; =============================================================================
;;; Contracts
;;; =============================================================================

(m/=> home [:=> [:cat EnvLike] [:maybe AbsPath]])
(m/=> resolve-base [:=> [:cat EnvLike :string [:maybe [:sequential :string]]] [:maybe AbsPath]])
(m/=> app-dir [:=> [:cat EnvLike BaseDirKind :string [:* :string]] [:maybe AbsPath]])
(m/=> current-base-dir [:=> [:cat BaseDirKind] [:maybe AbsPath]])
(m/=> current-app-dir [:=> [:cat BaseDirKind :string [:* :string]] [:maybe AbsPath]])
