(ns hive-system.shell.binary
  "Binary identity: which names on PATH denote a program.

   (bin :rg)     => \"rg\"
   (names :fd)   => [\"fd\" \"fdfind\"]
   (locate :fd)  => (ok {:path \"/usr/bin/fdfind\" :bin \"fdfind\"})

   ## What belongs here, and what does not

   A binary identity answers exactly one question: what is this program called
   where it is installed. It says nothing about how to install it (that is
   `shell.tools`, which owns provisioning) and nothing about how a pattern
   enters its argv (that is `shell.search`, which owns grammar). Both of those
   registries reference an id here rather than restating the names.

   ## Aliases

   An id is registered under `:binary/id` AND under every `:binary/aliases`
   member, all pointing at the same map, so a lookup is a plain `get` and the
   value always names its own canonical id. `shell.tools` has keyed ripgrep as
   `:ripgrep` since before `shell.search` keyed it `:rg`; both resolve, and
   neither registry has to know what the other calls it.

   ## Layout

   Collect (registry reads) / Promote (pure derivation over a Binary VALUE) /
   Boundary (`locate`, the only form here that touches PATH). The probe is a
   port, so a caller — a test above all — supplies its own adapter instead of
   redefining somebody's var."
  (:require [hive-dsl.result :as r]
            [hive-system.shell.detect :as detect]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Value objects
;;; =============================================================================

(def BinaryId
  "Stable keyword naming a program."
  :keyword)

(def Binary
  "A program's names, as data.

   :binary/bin      the upstream name, and the one an argv is built from.
   :binary/alts     other names the SAME program is installed under. Debian
                    ships fd as `fdfind` and bat as `batcat`, the upstream
                    names having gone to fdclone and bacula-console-qt. A
                    packaging fact: probing `:binary/bin` alone reports the
                    program missing while it sits on PATH.
   :binary/aliases  other ids that denote this same program."
  [:map {:closed true}
   [:binary/id BinaryId]
   [:binary/bin :string]
   [:binary/alts {:optional true} [:vector :string]]
   [:binary/aliases {:optional true} [:set BinaryId]]])

(def ProgramNames
  "Names to probe, upstream first. Non-empty: a Binary always has `:binary/bin`."
  [:vector {:min 1} :string])

(def BinaryKeys
  "Registry keys a Binary is reachable under. Non-empty: its own id is one."
  [:vector {:min 1} BinaryId])

;;; =============================================================================
;;; Ports
;;; =============================================================================

(defprotocol IProgramProbe
  "Does a program of this name exist on this host, and where."
  (-probe [this program-name]
    "Result<{:path .. :program ..}> for PROGRAM-NAME."))

(defrecord WhichProbe []
  IProgramProbe
  (-probe [_ program-name] (detect/which program-name)))

(def ^:dynamic *probe*
  "The probe `locate` uses when given none. Rebind to inject an adapter; the
   var is read at CALL time, so a binding is honoured by everything downstream
   — `shell.tools` and `shell.search` included — without either of them
   growing a probe parameter they have no opinion about."
  (->WhichProbe))

;;; =============================================================================
;;; The built-ins
;;; =============================================================================

(def built-in
  "Every program either registry names."
  [#:binary{:id :rg :bin "rg" :aliases #{:ripgrep}}
   #:binary{:id :fd :bin "fd" :alts ["fdfind"]}
   #:binary{:id :bat :bin "bat" :alts ["batcat"]}
   #:binary{:id :sd :bin "sd"}
   #:binary{:id :grep :bin "grep"}
   #:binary{:id :jq :bin "jq"}
   #:binary{:id :tree :bin "tree"}
   #:binary{:id :fzf :bin "fzf"}
   #:binary{:id :delta :bin "delta"}
   #:binary{:id :htop :bin "htop"}
   #:binary{:id :dust :bin "dust"}
   #:binary{:id :procs :bin "procs"}
   #:binary{:id :tokei :bin "tokei"}
   #:binary{:id :kubectl :bin "kubectl"}
   #:binary{:id :cloudflared :bin "cloudflared"}
   #:binary{:id :tmux :bin "tmux"}
   #:binary{:id :git :bin "git"}
   #:binary{:id :find :bin "find"}
   #:binary{:id :ls :bin "ls"}
   #:binary{:id :ps :bin "ps"}])

;;; =============================================================================
;;; Collect — registry reads
;;; =============================================================================

(defonce ^:private binaries* (atom {}))

(defn registered
  "Snapshot of {id -> Binary}, alias keys included."
  []
  @binaries*)

(defn canonical
  "Snapshot of {canonical-id -> Binary}, alias keys excluded."
  []
  (into (sorted-map)
        (filter (fn [[k v]] (= k (:binary/id v))))
        @binaries*))

(defn lookup
  "The Binary ID denotes, or nil. Resolves aliases."
  [id]
  (get @binaries* id))

;;; =============================================================================
;;; Promote — pure, over a Binary VALUE
;;; =============================================================================

(defn bin-of
  "The upstream name BINARY goes by."
  [binary]
  (:binary/bin binary))

(defn names-of
  "Every name BINARY may be installed under, upstream first. The probe order."
  [binary]
  (into [(:binary/bin binary)] (:binary/alts binary)))

(defn keys-of
  "Every registry key BINARY is reachable under: its id and every alias."
  [binary]
  (into [(:binary/id binary)] (:binary/aliases binary)))

(defn located
  "The answer for NAME having answered with RES, or nil if it did not.

   Reports the name that ANSWERED rather than the canonical one — that is the
   name a caller must spawn."
  [name res]
  (when (r/ok? res) (r/ok (assoc (:ok res) :bin name))))

;;; =============================================================================
;;; Registry writes
;;; =============================================================================

(defn register!
  "Register BINARY under its id and every alias. Result<Binary>.
   A map that does not conform to the Binary schema is refused."
  [binary]
  (if (m/validate Binary binary)
    (do (swap! binaries*
               (fn [m] (reduce (fn [acc k] (assoc acc k binary)) m (keys-of binary))))
        (r/ok binary))
    (r/err :binary/invalid {:binary binary :explain (m/explain Binary binary)})))

(defn unregister!
  "Drop the binary registered under ID, and every key that pointed at it.
   Returns it, or nil."
  [id]
  (let [prev (lookup id)]
    (when prev
      (swap! binaries*
             (fn [m]
               (reduce (fn [acc k] (if (= prev (get acc k)) (dissoc acc k) acc))
                       m
                       (keys-of prev)))))
    prev))

(defn register-built-in!
  "Register every built-in identity. Returns the vector of Results."
  []
  (mapv register! built-in))

(def ^:private bootstrap
  "Registers the built-in identities on load. `def`, not `defonce`: reloading
   this namespace must replace the identities it shipped, and registration is
   keyed by id and therefore idempotent."
  (register-built-in!))

;;; =============================================================================
;;; Facade — collect + promote
;;; =============================================================================

(defn bin
  "The upstream name ID denotes, or nil for an unregistered id."
  [id]
  (some-> (lookup id) bin-of))

(defn names
  "Every name ID may be installed under, upstream first, or nil for an
   unregistered id. This is the probe order."
  [id]
  (some-> (lookup id) names-of))

;;; =============================================================================
;;; Boundary — the only form here that touches PATH
;;; =============================================================================

(defn locate
  "Result<{:path .. :bin ..}>: the name ID is actually installed under HERE.

   Probes `names` in order through PROBE (default `*probe*`), stopping at the
   first that answers. Refuses naming every name it tried, rather than letting
   the caller meet the absence as an ENOENT from the fork.

   An unregistered id and an uninstalled program are DIFFERENT refusals:
   `:binary/unknown` says nobody declared this identity, `:binary/not-installed`
   says we looked and it is not here. Collapsing them would make \"I never
   looked\" indistinguishable from \"it is absent\"."
  ([id] (locate id *probe*))
  ([id probe]
   (if-let [b (lookup id)]
     (let [tried (names-of b)]
       (or (some (fn [n] (located n (-probe probe n))) tried)
           (r/err :binary/not-installed {:id id :tried tried})))
     (r/err :binary/unknown {:id id :known (vec (keys (canonical)))}))))

;;; =============================================================================
;;; Contracts
;;; =============================================================================

(m/=> bin-of [:=> [:cat Binary] :string])
(m/=> names-of [:=> [:cat Binary] ProgramNames])
(m/=> keys-of [:=> [:cat Binary] BinaryKeys])
(m/=> bin [:=> [:cat BinaryId] [:maybe :string]])
(m/=> names [:=> [:cat BinaryId] [:maybe ProgramNames]])
