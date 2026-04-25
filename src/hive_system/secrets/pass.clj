(ns hive-system.secrets.pass
  "GNU pass (password-store) ISecretBackend implementation.

   Resolves entries from the user's `pass` store into opaque Secret
   values. Never logs the resolved content. Stderr is captured but
   sanitized in error returns.

   ## API

   - `->PassBackend`         — defrecord constructor (preferred via DIP)
   - `pass-show`             — convenience: full output as one Secret
   - `pass-show-line`        — convenience: first non-empty line only
   - `pass-available?`       — convenience: Result<bool> backend health

   ## Backend errors

   - `:pass/not-found` — entry does not exist
   - `:pass/empty`     — entry exists but resolved to blank
   - `:pass/exec-fail` — `pass` binary failed (binary missing, gpg lock, etc.)
   - `:pass/timeout`   — pass invocation exceeded deadline

   Errors include the lookup `:key` (NOT the resolved value) for diagnostics."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.shell.core :as sh]
            [hive-system.secrets.core :as sec]
            [hive-system.secrets.protocols :as proto]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(def ^:private DEFAULT-TIMEOUT-MS 10000)

(defn- first-line
  "Return the first non-empty trimmed line of s, or \"\" if none."
  [s]
  (->> (str/split-lines (or s ""))
       (map str/trim)
       (drop-while str/blank?)
       first
       (#(or % ""))))

(defn- shell-result->secret
  "Translate a shell exec! result into Result<Secret> for the pass backend.
   Pure: takes the raw shell output map + key + line-only? flag."
  [shell-result key line-only?]
  (cond
    (r/err? shell-result)
    (r/err :pass/exec-fail
           {:key key
            :cause (:error shell-result)
            :cause-data (dissoc shell-result :error)})

    :else
    (let [{:keys [exit stdout stderr]} (:ok shell-result)
          out (or stdout "")]
      (cond
        (and (not (zero? exit))
             (re-find #"is not in the password store" (or stderr "")))
        (r/err :pass/not-found {:key key :stderr (str/trim stderr)})

        (not (zero? exit))
        (r/err :pass/exec-fail
               {:key key :exit exit :stderr (str/trim stderr)})

        :else
        (let [value (if line-only? (first-line out) out)]
          (if (str/blank? value)
            (r/err :pass/empty {:key key})
            (r/ok (sec/make-secret value :pass key))))))))

;; =============================================================================
;; Backend implementation
;; =============================================================================

(defrecord PassBackend [shell]
  proto/ISecretBackend

  (backend-id [_] :pass)

  (fetch [_ key {:keys [line-only? timeout-ms]
                 :or   {timeout-ms DEFAULT-TIMEOUT-MS}}]
    (let [exec-fn (or shell sh/exec!)
          result  (exec-fn ["pass" key] {:timeout-ms timeout-ms})]
      (shell-result->secret result key line-only?)))

  (available? [_]
    (let [which-result (sh/which "pass")]
      (if (r/err? which-result)
        (r/ok false)
        (let [home  (System/getenv "HOME")
              store (or (System/getenv "PASSWORD_STORE_DIR")
                        (str home "/.password-store"))
              f     (java.io.File. ^String store)]
          (r/ok (and (.isDirectory f)
                     (boolean (some-> (.listFiles f) seq)))))))))

(defn make-pass-backend
  "Construct a PassBackend.

   opts (all optional):
     :shell — exec function with the same shape as hive-system.shell.core/exec!
              (cmd, opts) → Result. Used for testing with a mock shell."
  ([] (make-pass-backend {}))
  ([{:keys [shell]}] (->PassBackend shell)))

;; =============================================================================
;; Convenience API — uses a default singleton PassBackend.
;; Prefer the protocol-based API in production for testability.
;; =============================================================================

(def ^:private default-backend (delay (make-pass-backend)))

(defn pass-show
  "Resolve `key` from the default pass backend, returning Result<Secret>.

   Errors:
     :pass/not-found, :pass/empty, :pass/exec-fail, :pass/timeout."
  ([key] (pass-show key {}))
  ([key opts]
   (proto/fetch @default-backend key opts)))

(defn pass-show-line
  "Like `pass-show`, but returns only the first non-empty line as the
   Secret. Use for single-line credentials (IPs, short tokens) where
   `pass` may include trailing notes/comments on subsequent lines."
  ([key] (pass-show-line key {}))
  ([key opts]
   (proto/fetch @default-backend key (assoc opts :line-only? true))))

(defn pass-available?
  "Result<bool>: true if `pass` binary is on PATH AND the password
   store directory exists and is non-empty."
  []
  (proto/available? @default-backend))
