(ns hive-system.pattern.protocols
  "Protocol for the pattern subsystem.

   ## ISP boundary

   `IPatternEngine` is the DIP seam between consumers (audits, linters, log
   scanners) and concrete matching engines (java.util.regex today; a structural
   s-expression matcher, a glob matcher, or a tree-sitter query engine next).

   Consumers depend on this protocol and on a Pattern value. They never name an
   engine, so swapping or adding one changes no call site.

   ## Engine contract

   An engine MUST:
   - Return `Result` from every operation — never throw for a bad pattern.
   - Reject a flag it cannot honour (`:pattern/unsupported-flag`) rather than
     ignore it: a silently dropped flag is a wrong answer.
   - Report matches in subject order, non-overlapping, `:match/end` exclusive,
     with `(subs subject start end)` equal to `:match/text`.
   - Use a stable, unique `engine-id` keyword.")

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(defprotocol IPatternEngine
  "A pluggable matching engine over a Pattern value object."
  (engine-id [this]
    "Keyword identifying this engine (e.g. :regex, :structural).
     MUST be stable and unique within a process.")
  (match? [this pattern subject]
    "Does PATTERN occur in SUBJECT? Returns Result<boolean>.")
  (scan [this pattern subject]
    "Every occurrence of PATTERN in SUBJECT. Returns Result<Matches> —
     subject-ordered, non-overlapping, `:match/end` exclusive."))
