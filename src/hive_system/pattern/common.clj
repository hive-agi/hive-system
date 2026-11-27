(ns hive-system.pattern.common
  "The named patterns the workspace kept writing as the same literal in many
   repositories (a 2026-11-26 census: `^[0-9a-f]{64}$` in 8 repos, the memory id
   in 4, `\\d+` in 17, ...). Each is a regal CONSTRUCT registered once under
   `:hive.pattern/*` and run through `hive-system.pattern.core`, so a call site
   names WHAT it looks for and never spells a regex.

     (common/matches? :hive.pattern/hex64 digest)

   `catalog` is data: each entry carries the construct, a doc, and `:replaces`,
   the Java regex source it is equivalent to. The carto recipe that rewrites
   literals reads `:replaces` to recognize a literal it can name."
  (:require [hive-system.pattern.construct.api :as api]
            [hive-system.pattern.core :as p]
            [hive-system.pattern.registry :as registry]
            [hive-system.pattern.schema :as ps]
            [malli.core :as m]
            [hive-dsl.result :as r]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private hex-digit [:class [\0 \9] [\a \f]])

(defn- hex [n] [:repeat hex-digit n n])

(defn- whole [& forms] (into [:cat :start] (conj (vec forms) :end)))

(def ^:private ascii-whitespace
  "Java's `\\s`, which is ASCII only; regal's `:whitespace` is Unicode-wide."
  [:class \space \tab \newline \u000B \formfeed \return])

(def CatalogEntry
  "One catalog entry, as a CLOSED map — an unrecognized key is a defect, not an
   extension point. `:form` is the regal construct. At least ONE of `:replaces`
   (the anchored Java source) or `:replaces-find` (the unanchored source) is
   present; an anchored concept carries `:replaces` (pinned by the golden test to
   the construct) and an `-anywhere` sibling may carry only `:replaces-find`.
   `:aliases` are OPTIONAL semantically EQUAL sources (same matches, so a rewrite
   cannot change behaviour); `:flags` is an OPTIONAL set threaded into the
   Pattern."
  [:and
   [:map {:closed true}
    [:form :any]
    [:doc :string]
    [:replaces {:optional true} :string]
    [:replaces-find {:optional true} :string]
    [:aliases {:optional true} [:vector :string]]
    [:flags {:optional true} [:set ps/Flag]]]
   [:fn {:error/message "a catalog entry needs :replaces or :replaces-find"}
    (fn [entry] (or (:replaces entry) (:replaces-find entry)))]])

(defn catalog-entry-valid?
  "True when ENTRY satisfies `CatalogEntry`. The gate the catalog's own test
   runs, so a typo'd key is caught at the source rather than at a call site."
  [entry]
  (m/validate CatalogEntry entry))

(m/=> catalog-entry-valid? [:=> [:cat :any] :boolean])

(def catalog
  "id -> `CatalogEntry`: the regal construct, a doc, the anchored `:replaces`,
   and — optionally — an unanchored `:replaces-find`, semantically EQUAL
   `:aliases`, and a `:flags` set. The carto recipe that rewrites literals reads
   `:replaces` and `:replaces-find` to recognize a literal it can name."
  {:hive.pattern/hex64     {:form (whole (hex 64)) :replaces "^[0-9a-f]{64}$"
                            :doc  "A whole SHA-256 digest in lower-case hex."}
   :hive.pattern/hex40     {:form (whole (hex 40)) :replaces "^[0-9a-f]{40}$"
                            :doc  "A whole git object id (SHA-1) in lower-case hex."}
   :hive.pattern/hex32     {:form (whole (hex 32)) :replaces "^[0-9a-f]{32}$"
                            :doc  "A whole 32-digit lower-case hex id."}
   :hive.pattern/uuid      {:form (whole (hex 8) "-" (hex 4) "-" (hex 4) "-" (hex 4) "-" (hex 12))
                            :replaces "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                            :doc  "A whole lower-case UUID."}
   :hive.pattern/memory-id {:form (whole [:repeat :digit 14 14] "-" (hex 8))
                            :replaces "^\\d{14}-[0-9a-f]{8}$"
                            :doc  "A whole hive memory entry id: 14 digits, a dash, 8 hex digits."}
   :hive.pattern/digits    {:form (whole [:+ :digit]) :replaces "^\\d+$"
                            :doc  "A whole run of decimal digits."}
   :hive.pattern/digits-anywhere
   {:form [:+ :digit] :replaces-find "\\d+"
    :doc  "A run of decimal digits ANYWHERE in the subject — the unanchored sibling of :hive.pattern/digits, for the `re-find #\"\\d+\"` sites (37 in hive)."}
   :hive.pattern/slug      {:form (whole [:class [\a \z]] [:* [:class [\a \z] [\0 \9] \-]])
                            :replaces "^[a-z][a-z0-9\\-]*$"
                            :doc  "A whole lower-case slug: a letter, then letters, digits and dashes."}
   :hive.pattern/ws-run    {:form [:+ ascii-whitespace]
                            :replaces "[ \t\n\u000B\f\r]+"
                            :aliases ["\\s+" "[\\s]+"]
                            :doc  "A run of ASCII whitespace, exactly Java's `\\s+`. The emitter writes the control characters raw, so `:replaces` holds them raw too. `\\s+` and `[\\s]+` are aliases: Java's `\\s` IS `[ \t\n\u000B\f\r]`, so they match the same strings and a rewrite cannot change behaviour. `\\s` alone (one char) and `[ \t]+` (no newline) are NOT aliases — they are separate clusters and get no entry unless they meet the bar on their own."}})

(defn register-all!
  "Register every `catalog` entry. Returns {id Result<Pattern>}."
  []
  (into (sorted-map)
        (map (fn [[id {:keys [form doc]}]]
               [id (api/register! {:pattern/id id :pattern/doc doc} form)]))
        catalog))

(def ^:private bootstrap
  "Registers the catalog on load. `def`, not `defonce`, so a reload re-registers."
  (register-all!))

(defn select-source
  "Result<String>: the Java source ENTRY compiles to under OPTS. PURE.

   Default is `:replaces`, the anchored whole-string form. `{:mode :find}`
   selects `:replaces-find`, the unanchored form; an entry that declares none is
   REFUSED (`:pattern/no-find-variant`) rather than silently falling back to the
   anchored source, because the two match different strings."
  [id entry {:keys [mode]}]
  (cond
    (nil? entry)                          (r/err :pattern/unknown {:id id})
    (and (= :find mode) (nil? (:replaces-find entry)))
    (r/err :pattern/no-find-variant {:id id})
    (= :find mode)                        (r/ok (:replaces-find entry))
    :else                                 (r/ok (or (:replaces entry) (:replaces-find entry)))))

(m/=> select-source [:=> [:cat :keyword :any [:map]] :any])

(defn matches?
  "True when the catalog pattern `id` occurs in `s`. A non-string `s` is false.
   An id outside the registry is false too; `catalog-registered?` is the test
   that keeps every catalog id resolvable.

   With OPTS the call returns Result<boolean> and can say more than the
   whole-string form:

     (matches? :hive.pattern/digits-anywhere s {:mode :find})
     (matches? :hive.pattern/uuid s {:flags #{:case-insensitive}})

   `:mode :find` matches the entry's `:replaces-find` \u2014 its unanchored form \u2014
   and REFUSES with `:pattern/no-find-variant` when the entry declares none,
   because a concept with no unanchored form must not be searched unanchored by
   accident. `:flags` are threaded into the Pattern before `compile-pattern`,
   united with any `:flags` the entry itself declares; a flag the engine cannot
   honour is refused (`:pattern/unsupported-flag`), never dropped."
  ([id s]
   (boolean (and (string? s) (true? (:ok (p/match? id s))))))
  ([id s opts]
   (if-not (string? s)
     (r/ok false)
     (let [entry (get catalog id)
           fs    (into (or (:flags entry) #{}) (or (:flags opts) #{}))]
       (r/let-ok [src (select-source id entry opts)]
                 (p/match? (cond-> {:pattern/expr src}
                             (seq fs) (assoc :pattern/flags fs))
                           s))))))

(defn catalog-registered?
  "True when every `catalog` id resolves in the live registry."
  []
  (every? (set (keys (registry/registered-patterns))) (keys catalog)))
