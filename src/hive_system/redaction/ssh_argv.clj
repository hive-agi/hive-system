(ns hive-system.redaction.ssh-argv
  "Structural redactor for ssh argv vectors.

   ## Goal

   Preserve the *shape* of the argv (every flag in its place, every
   option preserved, count unchanged) while replacing Tainted slots with
   stable hash tokens like `<host:#a3f4>` / `<id:#7c2>`.

   The redactor is structurally aware: it understands the standard
   ssh(1) flag syntax and knows which slots can hold a hostname /
   identity / port. But it is intentionally CONSERVATIVE — it ONLY
   touches slots whose contents are `Tainted`. Plain strings pass
   through unchanged.

   ## Why conservative

   A hostname is whatever the user happens to call their VPS. We don't
   want to pattern-match hostnames (false positives, false negatives).
   Instead, the credential resolver / plan compiler decides what is
   sensitive by wrapping in `Tainted`. The redactor's job is to take
   that signal and present it as a token rather than a `<redacted ...>`
   blob — preserving structural fidelity for debugging.

   ## Recognized ssh flag idioms

   Single-arg flags (the next argv slot is the value):

     -l <user>          → identity
     -i <keyfile>       → identity (keyfile path)
     -p <port>          → port
     -o <key=val>       → option (passed through; we don't parse it)
     -F, -E, -S, -W, -L, -R, -D, -J, -Q, -e, -m, -c, -O, -B
        (each of the above takes a value in the following slot)

   Boolean flags (no following value): -1 -2 -4 -6 -A -a -C -f -G -g
     -K -k -M -N -n -q -s -T -t -V -v -X -x -Y -y

   Anything that doesn't look like a flag and appears after we've
   consumed flags is treated as the destination (host, or user@host).

   ## Behavior

   Plain strings: pass through verbatim.
   Tainted slots: replaced with their `<src:#hash>` token form. If a
                  Tainted carries `:source` :argv-host, you get
                  `<host:#xxxx>`; for :argv-id you get `<id:#xxxx>`;
                  the source label IS the token prefix.

   Repeated Tainted with the same underlying value within a single
   argv produces the SAME token (because the hash is value-stable
   within a JVM). Operators can spot \"this argv references the same
   host twice\" at a glance.

   The function does NOT call untaint and does NOT lengthen or shorten
   the argv. Output count == input count."
  (:require [hive-system.redaction.tainted :as tainted]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Slot-token helpers
;; =============================================================================

(defn- slot->token
  "If `slot` is Tainted, return its token form `<src:#hash>`; otherwise
   return `slot` unchanged.

   `default-source` is used as the prefix when the Tainted's :source is
   absent or non-string/keyword — so callers can ensure a sensible
   token like `<host:#xxxx>` even if upstream forgot to label it."
  [slot default-source]
  (if (tainted/tainted? slot)
    (let [s    (:source slot)
          pref (cond
                 (keyword? s) (name s)
                 (string? s)  s
                 :else        (name default-source))]
      (str "<" pref ":#" (:hash slot) ">"))
    slot))

;; =============================================================================
;; Flag classification
;; =============================================================================

(def ^:private value-flags
  "ssh flags that consume the NEXT argv slot as their value."
  #{"-l" "-i" "-p" "-o" "-F" "-E" "-S" "-W" "-L" "-R" "-D" "-J"
    "-Q" "-e" "-m" "-c" "-O" "-B" "-b"})

(defn- value-flag? [s]
  (and (string? s) (contains? value-flags s)))

(defn- flag? [s]
  (and (string? s)
       (.startsWith ^String s "-")))

;; =============================================================================
;; Per-flag slot semantics
;;
;; For a value-flag's argument, we know the SOURCE label even if upstream
;; didn't annotate the Tainted. -l takes an identity, -i takes an
;; identity (keyfile), -p takes a port. We pass the appropriate default
;; source down so a bare-Tainted produces the right token prefix.
;; =============================================================================

(defn- default-source-for-flag [flag]
  (case flag
    "-l" "id"
    "-i" "id"
    "-p" "port"
    "host"))

;; =============================================================================
;; Public API
;; =============================================================================

(defn redact-ssh-argv
  "Redact an SSH argv vector, preserving structure (flag positions and
   total count) but replacing any Tainted slots with stable hash tokens
   like `<host:#a3f4>`.

   Returns a vector of the same length as `argv`. Plain strings pass
   through untouched. Tainted slots become token strings.

   The redactor walks left-to-right:
     - When it sees a value-flag (e.g. \"-l\"), the NEXT slot is treated
       as that flag's value with a flag-appropriate default source
       (\"id\" for -l/-i, \"port\" for -p).
     - When it sees a non-flag slot at \"host position\" (after
       flag-and-value pairs are consumed), Tainted slots get the \"host\"
       prefix by default.
     - Plain strings are NEVER hashed — the redactor does not guess
       which non-Tainted slot might be sensitive."
  [argv]
  (when-not (sequential? argv)
    (throw (ex-info "argv must be sequential" {:argv argv})))
  (let [v (vec argv)
        n (count v)]
    (loop [i      0
           out    (transient [])]
      (if (>= i n)
        (persistent! out)
        (let [slot (nth v i)]
          (cond
            ;; A value-flag: keep the flag verbatim, then redact the
            ;; following slot with the flag's default source.
            (value-flag? slot)
            (let [next-i  (inc i)
                  default (default-source-for-flag slot)]
              (if (< next-i n)
                (recur (+ i 2)
                       (-> out
                           (conj! slot)
                           (conj! (slot->token (nth v next-i) default))))
                ;; Trailing value-flag with no value — preserve as-is.
                (recur (inc i) (conj! out slot))))

            ;; A boolean flag (any other -X token): pass through.
            (flag? slot)
            (recur (inc i) (conj! out slot))

            ;; Non-flag slot in host position: default source = "host".
            :else
            (recur (inc i)
                   (conj! out (slot->token slot "host")))))))))
