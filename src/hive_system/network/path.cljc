(ns hive-system.network.path
  "Where a hive Unix-domain socket lives (STD-04 T2). Pure: no IO, no clock.

   Rule:
     $XDG_RUNTIME_DIR/hive/<service>[-<id>].sock          when XDG_RUNTIME_DIR is set
     <java.io.tmpdir>/hive-<uid>/<service>[-<id>].sock    otherwise

   The directory is created 0700 and the socket set 0600 by the effectful
   adapter (hive-system.network.unix); this namespace only computes the
   path and refuses one longer than `max-path-bytes` (sun_path is 108 bytes
   on Linux and 104 on macOS, so 100 leaves room on both).

   Every fn returns a hive-dsl Result."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def max-path-bytes
  "Longest socket path, in UTF-8 bytes, the rule accepts."
  100)

(def ^:private name-re
  "A service or id: letters, digits, dot, underscore, dash; no leading dot."
  #"[A-Za-z0-9_\-][A-Za-z0-9._\-]*")

(defn utf8-length
  "Number of bytes `s` takes in UTF-8."
  [s]
  #?(:clj  (alength (.getBytes ^String s "UTF-8"))
     :cljs (.-length (.encode (js/TextEncoder.) s))))

(defn- blank->nil [s]
  (when-not (str/blank? s) s))

(defn- strip-trailing-slash [s]
  (if (and (> (count s) 1) (str/ends-with? s "/"))
    (recur (subs s 0 (dec (count s))))
    s))

(defn socket-dir
  "The directory hive sockets of this user live in. `env` is a map of
   environment variable name to value (strings); `tmpdir` is the value of
   java.io.tmpdir; `uid` the numeric user id.
   => Result<string>"
  [env tmpdir uid]
  (if-let [xdg (blank->nil (get env "XDG_RUNTIME_DIR"))]
    (r/ok (str (strip-trailing-slash xdg) "/hive"))
    (cond
      (str/blank? tmpdir)
      (r/err :socket-path/no-base {:message "neither XDG_RUNTIME_DIR nor tmpdir is set"})

      (nil? uid)
      (r/err :socket-path/no-uid {:message "uid is required when XDG_RUNTIME_DIR is unset"})

      :else
      (r/ok (str (strip-trailing-slash tmpdir) "/hive-" uid)))))

(defn socket-file-name
  "<service>[-<id>].sock, after checking both names.
   => Result<string>"
  ([service] (socket-file-name service nil))
  ([service id]
   (let [svc (some-> service str)
         id  (some-> id str)]
     (cond
       (or (nil? svc) (not (re-matches name-re svc)))
       (r/err :socket-path/bad-service {:service service
                                        :message "service must match [A-Za-z0-9_-][A-Za-z0-9._-]*"})

       (and (some? id) (not (re-matches name-re id)))
       (r/err :socket-path/bad-id {:id id
                                   :message "id must match [A-Za-z0-9_-][A-Za-z0-9._-]*"})

       :else
       (r/ok (str svc (when id (str "-" id)) ".sock"))))))

(defn socket-path
  "The socket path of `service` (and optional `id`) under the T2 rule.
   Refuses a path longer than `max-path-bytes` UTF-8 bytes.
   => Result<{:path string :dir string}>"
  ([env tmpdir uid service] (socket-path env tmpdir uid service nil))
  ([env tmpdir uid service id]
   (r/let-ok [dir  (socket-dir env tmpdir uid)
              file (socket-file-name service id)]
     (let [path  (str dir "/" file)
           bytes (utf8-length path)]
       (if (> bytes max-path-bytes)
         (r/err :socket-path/too-long {:path path :bytes bytes :max max-path-bytes
                                       :message (str "socket path is " bytes " bytes, the limit is "
                                                     max-path-bytes)})
         (r/ok {:path path :dir dir}))))))
