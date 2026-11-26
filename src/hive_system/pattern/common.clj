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
            [hive-system.pattern.registry :as registry]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private hex-digit [:class [\0 \9] [\a \f]])

(defn- hex [n] [:repeat hex-digit n n])

(defn- whole [& forms] (into [:cat :start] (conj (vec forms) :end)))

(def ^:private ascii-whitespace
  "Java's `\\s`, which is ASCII only; regal's `:whitespace` is Unicode-wide."
  [:class \space \tab \newline \u000B \formfeed \return])

(def catalog
  "id -> {:form regal-construct :doc string :replaces java-regex-source}."
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
   :hive.pattern/slug      {:form (whole [:class [\a \z]] [:* [:class [\a \z] [\0 \9] \-]])
                            :replaces "^[a-z][a-z0-9\\-]*$"
                            :doc  "A whole lower-case slug: a letter, then letters, digits and dashes."}
   :hive.pattern/ws-run    {:form [:+ ascii-whitespace]
                            :replaces "[ \t\n\u000B\f\r]+"
                            :doc  "A run of ASCII whitespace, exactly Java's `\\s+`. The emitter writes the control characters raw, so `:replaces` holds them raw too."}})

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

(defn matches?
  "True when the catalog pattern `id` occurs in `s`. A non-string `s` is false.
   An id outside the registry is false too; `catalog-registered?` is the test
   that keeps every catalog id resolvable."
  [id s]
  (boolean (and (string? s) (true? (:ok (p/match? id s))))))

(defn catalog-registered?
  "True when every `catalog` id resolves in the live registry."
  []
  (every? (set (keys (registry/registered-patterns))) (keys catalog)))
