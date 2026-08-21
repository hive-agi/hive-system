(ns hive-system.pattern.schema
  "Malli value objects for the pattern subsystem.

   A Pattern is a portable, ENGINE-AGNOSTIC description of what to look for:
   an expression plus flags, optionally named by an id. A Match is one located
   occurrence — text plus its half-open [start end) offsets in the subject.

   These schemas are the single source: they drive the `m/=>` contracts and the
   synthesized property/mutation tests.")

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def Flag
  "Portable matching flag. Engines map these onto their own dialect and MUST
   ignore none silently — an unsupported flag is an error, not a no-op."
  [:enum :case-insensitive :multiline :dotall :extended])

(def EngineId
  "Stable keyword naming a registered engine (e.g. :regex, :structural)."
  :keyword)

(def Pattern
  "What to look for. :pattern/engine absent means the caller's default engine.

   :pattern/construct is present when the expression was PROJECTED from a
   regex construct (see hive-system.pattern.construct.api) rather than written
   as a literal. It records the source of :pattern/expr; nothing in the match
   path reads it."
  [:map {:closed true}
   [:pattern/id {:optional true} :keyword]
   [:pattern/engine {:optional true} EngineId]
   [:pattern/expr :string]
   [:pattern/flags {:optional true} [:set Flag]]
   [:pattern/construct {:optional true} :any]
   [:pattern/doc {:optional true} :string]])

(def PatternRef
  "A call site names a pattern by id or supplies one inline."
  [:or :keyword Pattern])

(def PatternIndex
  "id -> Pattern. The registry's value; passed explicitly to pure resolvers."
  [:map-of :keyword Pattern])

(def Match
  "One occurrence. :match/end is EXCLUSIVE. :match/groups holds capture groups
   in declaration order, nil for a group that did not participate."
  [:map {:closed true}
   [:match/text :string]
   [:match/start [:int {:min 0}]]
   [:match/end [:int {:min 0}]]
   [:match/groups [:vector [:maybe :string]]]])

(def Matches
  "Occurrences in subject order, non-overlapping."
  [:sequential Match])
