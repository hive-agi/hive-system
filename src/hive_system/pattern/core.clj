(ns hive-system.pattern.core
  "Facade for the pattern subsystem: name what you are looking for, get an
   answer, never mention an engine.

     (pattern/register-pattern! #:pattern{:id :audit/probe :expr \"ready\\\\?\"})
     (pattern/match? :audit/probe source)
     (pattern/scan  :audit/probe source)

   The regex engine registers itself on load, so `:regex` is available without
   ceremony; `*default-engine*` selects what an engine-less Pattern uses.

   Re-exports are DELEGATING fns, never def-aliases — a def alias of a protocol
   method freezes its method cache."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.protocols :as proto]
            [hive-system.pattern.regex :as regex]
            [hive-system.pattern.registry :as registry]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:dynamic *default-engine*
  "Engine used by a Pattern that names none."
  :regex)

(def ^:private bootstrap
  "Registers the regex engine on load.

   `def`, not `defonce`: reloading `pattern.regex` or `pattern.protocols`
   recompiles `RegexEngine` / `IPatternEngine`, and an instance minted before
   the recompile no longer satisfies the protocol — `match?` then throws
   \"No implementation of method\" against a registry holding an orphan.
   Re-registering on every load replaces it; safe because registration is keyed
   by engine-id and therefore idempotent."
  (registry/register-engine! (regex/make-engine)))

(defn- resolved
  "Result<[Pattern IPatternEngine]> for REF."
  [ref]
  (r/let-ok [pattern (registry/pattern ref)
             engine  (registry/engine (or (:pattern/engine pattern)
                                          *default-engine*))]
            (r/ok [pattern engine])))

(defn match?
  "Does REF occur in SUBJECT? Returns Result<boolean>."
  [ref subject]
  (r/let-ok [[pattern engine] (resolved ref)]
            (proto/match? engine pattern subject)))

(defn scan
  "Every occurrence of REF in SUBJECT. Returns Result<Matches>."
  [ref subject]
  (r/let-ok [[pattern engine] (resolved ref)]
            (proto/scan engine pattern subject)))

(defn find-first
  "The first occurrence of REF in SUBJECT, or nil. Returns Result<Match?>."
  [ref subject]
  (r/let-ok [matches (scan ref subject)]
            (r/ok (first matches))))

(defn register-pattern!
  "Register a named Pattern. Returns Result<Pattern>."
  [pattern]
  (registry/register-pattern! pattern))

(defn register-engine!
  "Register an IPatternEngine. Returns the engine."
  [engine]
  (registry/register-engine! engine))
