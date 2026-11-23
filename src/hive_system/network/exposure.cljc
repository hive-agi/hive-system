(ns hive-system.network.exposure
  "Exposure policy shared by every TCP listener in hive (STD-04 T7).

   One rule, stated once: a listener with no secret answers anyone who can
   reach it, so it binds loopback only, whatever was requested. With a
   secret the requested host wins, default all interfaces, and every call
   must carry `Authorization: Bearer <secret>`, compared in constant time so
   a caller cannot learn the secret by timing.

   A browser can still reach a loopback listener on the user's behalf (DNS
   rebinding, a hostile page posting to localhost), so the Origin and Host
   headers of a request are checked to be loopback as well:
   127.0.0.1, ::1 or localhost, any port.

   Pure: no I/O, no state. Same behaviour as hive-mcp.transport.exposure
   for bind-host and bearer-ok?."
  (:require [clojure.string :as str]
            [malli.core :as m])
  #?(:clj (:import [java.security MessageDigest])))
;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(def loopback "127.0.0.1")

(def all-interfaces "0.0.0.0")

(def loopback-hosts
  "Host names that mean this machine only. Compared lower-cased; an IPv6
   literal is compared without its brackets."
  #{"127.0.0.1" "::1" "localhost"})

(def Secret
  "A shared secret or token; blank or nil means none is configured."
  [:maybe :string])

(def Host
  "An interface to listen on: a requested host string, or one of the two
   defaults."
  [:string {:min 1}])

(defn bind-host
  "The interface to listen on. Loopback when SECRET is blank, whatever was
   REQUESTED. Otherwise REQUESTED, default all interfaces."
  [secret requested]
  (cond
    (str/blank? secret)    loopback
    (str/blank? requested) all-interfaces
    :else                  requested))

;; A blank (but non-empty) requested host passes through only with a secret,
;; and only when not blank, so the answer is never blank.
(m/=> bind-host [:=> [:cat Secret [:maybe :string]] Host])

(defn- utf8-bytes [s]
  #?(:clj  (.getBytes ^String s "UTF-8")
     :cljs (.encode (js/TextEncoder.) s)))

(defn constant-time=
  "True when byte arrays A and B are equal. The time taken depends on the
   length of A only, never on where the first difference is."
  [a b]
  #?(:clj  (MessageDigest/isEqual ^bytes a ^bytes b)
     :cljs (let [la (alength a) lb (alength b)]
             (if (zero? lb)
               (zero? la)
               (loop [i 0 acc (bit-xor la lb)]
                 (if (< i la)
                   (recur (inc i)
                          (bit-or acc (bit-xor (aget a i) (aget b (mod i lb)))))
                   (zero? acc)))))))

(defn bearer-ok?
  "True when SECRET is blank (no auth configured), or AUTH-HEADER is exactly
   `Bearer SECRET`. The comparison is constant-time."
  [secret auth-header]
  (or (str/blank? secret)
      (constant-time= (utf8-bytes (str auth-header))
                      (utf8-bytes (str "Bearer " secret)))))

;; The header is read with `str`, so a missing header (nil) is a refusal, not
;; a throw.
(m/=> bearer-ok? [:=> [:cat Secret [:maybe :string]] :boolean])

(def ^:private authority-re
  "host[:port], where host is a name, an IPv4 literal or a bracketed IPv6
   literal. Groups: bracketed IPv6 body, plain host, port."
  #"^(?:\[([0-9A-Fa-f:.]+)\]|([^\[\]:/?#@\s]+))(?::(\d{1,5}))?$")

(defn- port-ok? [port]
  (or (nil? port)
      (<= 0 (#?(:clj parse-long :cljs js/parseInt) port) 65535)))

(defn- loopback-authority?
  "True when AUTHORITY (host[:port]) names a loopback host."
  [authority]
  (boolean
   (when (string? authority)
     (when-let [[_ v6 host port] (re-matches authority-re authority)]
       (and (port-ok? port)
            (contains? loopback-hosts (str/lower-case (or v6 host))))))))

(defn loopback-host?
  "True when a Host header value names this machine only: 127.0.0.1, [::1]
   or localhost, any port. Missing, blank or anything else is false."
  [host-header]
  ;; A bare ::1 is not a valid Host (IPv6 must be bracketed) but it can only
  ;; mean loopback, so it is admitted; in an Origin it is refused.
  (or (= "::1" host-header) (loopback-authority? host-header)))

(m/=> loopback-host? [:=> [:cat [:maybe :string]] :boolean])

(def ^:private origin-re
  "scheme://authority, an RFC 6454 serialized origin: no path, query or
   fragment."
  #"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]+)$")

(defn loopback-origin?
  "True when an Origin header value is an http or https origin on this
   machine only: 127.0.0.1, [::1] or localhost, any port. Missing, the
   opaque `null` origin, another scheme or another host is false.

   A request with no Origin at all is not from a browser; whether to admit
   it is the listener's choice, see `origin-ok?`."
  [origin]
  (boolean
   (when (string? origin)
     (when-let [[_ scheme authority] (re-matches origin-re origin)]
       (and (#{"http" "https"} (str/lower-case scheme))
            (loopback-authority? authority))))))

(m/=> loopback-origin? [:=> [:cat [:maybe :string]] :boolean])

(defn origin-ok?
  "True when ORIGIN is absent (a non-browser client sends none) or a
   loopback origin."
  [origin]
  (or (nil? origin) (loopback-origin? origin)))

(m/=> origin-ok? [:=> [:cat [:maybe :string]] :boolean])
