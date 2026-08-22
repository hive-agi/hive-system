(ns hive-system.pattern.construct.regal
  "COLLECT layer: an anti-corruption layer over lambdaisland/regal, and the
   three dialect profiles it can render.

   Regal is the emitter we buy rather than build — it owns escaping, precedence
   and grouping, and it is the only code here that knows what a regex looks
   like. Its vocabulary does not cross into the domain: it throws, we return a
   Result; it names flavors, we name dialects.

   ## What regal does not do, and this layer must

   Measured on 0.1.175: regal does NOT gate on flavor. `[:atomic \"ab\"]` renders
   as `(?>ab)` under `:ecma`, where JavaScript has no atomic groups, and an
   unknown flavor is accepted silently. The capability gate in
   `construct.dialect` is therefore load-bearing, not ceremony.

   ## Dialects shipped

     :java  every capability            flavor :java9
     :ecma  no atomic groups            flavor :ecma
     :re2   no lookaround, no atomic    flavor :ecma  (rg, sd, RE2, Rust regex)

   `:posix-ere` is deliberately absent: ERE has no non-capturing group, so
   regal's `(?:…)` output is not ERE even after a capability gate. It needs a
   real second emitter, which this design declines to build."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.construct.core :as cc]
            [hive-system.pattern.construct.dialect :as dial]
            [lambdaisland.regal :as regal]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; Profiles — behaviour as data
;;; =============================================================================

(def java
  "The JVM's own engine: `java.util.regex`."
  #:dialect{:id :java
            :capabilities #{:lookaround :atomic :lazy :perl-class :capture
                            :control-escape :collation-range}
            :flavor :java
            :doc "java.util.regex — the engine behind the default IPatternEngine."})

(def ecma
  "JavaScript / ECMAScript. No atomic groups."
  #:dialect{:id :ecma
            :capabilities #{:lookaround :lazy :perl-class :capture
                            :control-escape :collation-range}
            :flavor :ecma
            :doc "ECMAScript RegExp — no atomic groups."})

(def re2
  "RE2 and Rust's regex crate — what `rg` and `sd` run. Linear-time by
   construction, which is exactly why it has no lookaround and no backrefs."
  #:dialect{:id :re2
            :capabilities #{:lazy :perl-class :capture :control-escape
                            :collation-range}
            :flavor :ecma
            :doc "RE2 / Rust regex — the dialect of rg and sd."})

(def built-in
  "Every profile this namespace ships."
  [java ecma re2])

;;; =============================================================================
;;; The adapter
;;; =============================================================================

(defrecord RegalEmitter [profile]
  dial/IConstructEmitter
  (dialect [_] profile)
  (-render [_ construct]
    (r/try-effect* :construct/render-failed
                   (str (regal/regex (cc/->regal construct)
                                     {:flavor (:dialect/flavor profile)})))))

(defn make-emitter
  "An emitter rendering through regal for PROFILE."
  [profile]
  (->RegalEmitter profile))

(defn register-built-in!
  "Register every built-in profile. Returns the vector of Results."
  []
  (mapv (comp dial/register-emitter! make-emitter) built-in))

(def ^:private bootstrap
  "Registers the built-in profiles on load.

   `def`, not `defonce`: reloading this namespace recompiles `RegalEmitter`, and
   an instance minted before the recompile no longer satisfies the protocol.
   Re-registering on every load replaces those orphans; it is safe because
   registration is keyed by dialect id and therefore idempotent."
  (register-built-in!))
