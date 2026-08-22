(ns hive-system.shell.search
  "Building an argv for a pattern-taking CLI from a Construct.

   ## What this is for

   Callers used to hand-assemble a pattern string and hand it to `rg`. A
   lookahead in that string reaches rg, which rejects it at runtime with

     regex parse error: look-around, including look-ahead and look-behind,
     is not supported

   — a failure the caller can only discover by spawning a process and then
   parsing English out of stderr. The dialect gate already knows the answer
   from the shape of the construct, so the refusal belongs here, before the
   fork, naming the missing capability as data.

   With `grep` the argument is stronger still. GNU grep does not reject what it
   cannot do: `grep -E '\\d+'` matches a literal `d`, exit 0, no warning. There
   the gate is not saving the caller a stderr parse, it is saving them a wrong
   answer they had no way to notice.

   ## Tools are data, not code

   A tool is a `Tool` map: which dialect it speaks, what it needs in order to
   speak it, and how a pattern enters its argv. Adding `ugrep` is a `register!`
   call, not an edit to `argv` — the open set gets a registry, not a `case`.

   ## What is measured

   An argv is a claim about a program's parser, and only that program can
   settle it. `rg`, `sd` and `grep` are driven for real by the suite, and the
   separator rule `argv` applies is what those runs established.

   `fd` is measured too, as of fd 9.0.0: sd's positional shape holds for it,
   including the negative control — strip the `--` and fd reads `-dash-[0-9]+`
   as `--max-depth ash-[0-9]+` and exits 2. What that run also established is
   that the argv was not the whole claim. Debian installs the binary as
   `fdfind`, so the shape was right, the program was present, and the command
   was still unrunnable. Hence `executable` and `spawn-argv`: `argv` states the
   grammar, and resolving argv[0] against PATH is a separate question with its
   own refusal.

   A PATH `grep` is frequently ugrep or another superset, which would accept
   constructs POSIX ERE cannot express. That only ever widens what runs, never
   narrows it, so emitting strict ERE stays correct whichever binary answers."
  (:require [hive-dsl.result :as r]
            [hive-system.pattern.construct.api :as api]
            [hive-system.pattern.construct.ere]
            [hive-system.pattern.construct.schema :as cs]
            [malli.core :as m]
            [hive-system.shell.detect :as detect]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;;; =============================================================================
;;; The value object
;;; =============================================================================

(def ToolId
  "Stable keyword naming a registered tool (:rg, :sd, :fd).

   Distinct from a DialectId even where the two spell the same word: a tool is a
   binary with an argv grammar, a dialect is a regex language, and one dialect
   serves many tools."
  :keyword)

(def Tool
  "A pattern-taking CLI, as data.

   :tool/flag           how the pattern is introduced, or nil if it is
                        positional. A flag such as `--regexp` also stops a
                        pattern that begins with `-` from being read as a flag.
   :tool/separator      the tool's end-of-flags separator, or nil if it has none.
   :tool/dialect-flags  what the tool needs in order to speak `:tool/dialect` at
                        all — `grep` reads BRE until `-E` says otherwise. Not
                        derivable from the dialect: it is a fact about this
                        binary's CLI.
   :tool/bin-alts       other names the SAME program is installed under. Debian
                        ships fd as `fdfind`, the name `fd` having already gone
                        to fdclone. A packaging fact, derivable from neither
                        `:tool/bin` nor the dialect, and the reason an argv can
                        be perfectly shaped and still unrunnable.

   Where the separator GOES is DERIVED from `:tool/flag` — see `argv`. A field
   declaring it would be a second copy of a decision `:tool/flag` already makes."
  [:map
   [:tool/id ToolId]
   [:tool/bin :string]
   [:tool/dialect cs/DialectId]
   [:tool/flag [:maybe :string]]
   [:tool/separator [:maybe :string]]
   [:tool/dialect-flags {:optional true} [:vector :string]]
   [:tool/bin-alts {:optional true} [:vector :string]]
   [:tool/doc {:optional true} :string]])

;;; =============================================================================
;;; Profiles — behaviour as data
;;; =============================================================================

(def ripgrep
  ;; `--regexp` protects the pattern, so `--` is left to protect the paths.
  #:tool{:id :rg :bin "rg" :dialect :re2
         :flag "--regexp" :separator "--"
         :doc "ripgrep — Rust regex. Linear time, and therefore no lookaround."})

(def sd
  ;; `sd PATTERN REPLACEMENT [files]` — every operand is positional, the pattern
  ;; included, so the separator has to come before the pattern to protect any of
  ;; them. Measured against sd 1.0.0.
  #:tool{:id :sd :bin "sd" :dialect :re2
         :flag nil :separator "--"
         :doc "sd — Rust regex find-and-replace. Pattern and replacement are both positional."})

(def fd
  ;; `fd -- PATTERN PATH`, measured against fd 9.0.0. sd's shape holds: `--`
  ;; before the positional pattern is load-bearing — without it `-dash-[0-9]+`
  ;; is read as `--max-depth ash-[0-9]+` and fd exits 2 — and the search path
  ;; follows the pattern with no second separator.
  ;;
  ;; Debian and Ubuntu install the binary as `fdfind`. The argv shape does not
  ;; change with the packaging; only argv[0] does, which is why the name is
  ;; data here and resolved by `executable` rather than assumed by `argv`.
  #:tool{:id :fd :bin "fd" :bin-alts ["fdfind"] :dialect :re2
         :flag nil :separator "--"
         :doc "fd — Rust regex over filenames. Pattern is positional."})

(def grep
  ;; `-E` is what makes grep read ERE rather than BRE, and `-e` introduces the
  ;; pattern so a leading `-` is not read as a flag. `--` then guards the paths.
  ;;
  ;; A PATH `grep` is routinely ugrep or another superset. That is safe in this
  ;; direction only: everything :posix-ere emits, a superset also accepts. It is
  ;; the reason the dialect emits ERE rather than trusting whatever is on PATH.
  #:tool{:id :grep :bin "grep" :dialect :posix-ere
         :flag "-e" :separator "--" :dialect-flags ["-E"]
         :doc "grep -E — POSIX ERE. No \\d, no lazy, no lookaround, no non-capturing group."})

(def built-in
  "Every profile this namespace ships."
  [ripgrep sd fd grep])

;;; =============================================================================
;;; Registry
;;; =============================================================================

(defonce ^:private tools* (atom {}))

(defn register!
  "Register TOOL under its id, replacing any prior one. Result<Tool>.
   A profile that does not conform to the Tool schema is refused."
  [tool]
  (if (m/validate Tool tool)
    (do (swap! tools* assoc (:tool/id tool) tool)
        (r/ok tool))
    (r/err :search/invalid-tool {:tool tool :explain (m/explain Tool tool)})))

(defn unregister!
  "Drop the tool registered under ID. Returns it, or nil."
  [id]
  (let [prev (get @tools* id)]
    (swap! tools* dissoc id)
    prev))

(defn registered
  "Snapshot of {tool-id -> Tool}."
  []
  @tools*)

(defn tool
  "Result<Tool> for ID."
  [id]
  (if-let [t (get @tools* id)]
    (r/ok t)
    (r/err :search/unknown-tool {:id id :known (vec (sort (keys @tools*)))})))

(defn register-built-in!
  "Register every built-in profile. Returns the vector of Results."
  []
  (mapv register! built-in))

(def ^:private bootstrap
  "Registers the built-in profiles on load. `def`, not `defonce`: reloading
   this namespace must replace the profiles it shipped, and registration is
   keyed by tool id and therefore idempotent."
  (register-built-in!))

;;; =============================================================================
;;; The boundary
;;; =============================================================================

(defn argv
  "Result<vector<string>>: the argv running TOOL-ID against FORM.

   FORM is regal's authored syntax or a normalized Construct. If the tool's
   dialect cannot express it the Result is the dialect's own refusal —
   `:construct/unsupported`, with `:missing` naming the capabilities — and no
   process is ever spawned.

   opts:
     :flags     — argv entries placed before the pattern
     :operands  — argv entries placed after it (rg/grep: paths; sd: the
                  replacement, then files)

   ## Where the separator goes

   `--` is placed as early as the tool's grammar allows, which is decided by
   whether a flag introduces the pattern:

     flag-introduced pattern — the flag already protects the pattern, so `--`
                               guards the operands, and is emitted only when
                               there are operands to guard.
     positional pattern      — `--` must precede the PATTERN, or a pattern such
                               as `-\\d+` is read as a flag. One separator then
                               covers the operands as well.

   (argv :rg [:cat [:+ :digit] \"-\"] {:operands [\"src\"]})
   => (ok [\"rg\" \"--regexp\" \"\\\\d+-\" \"--\" \"src\"])

   (argv :sd [:+ :digit] {:operands [\"N\" \"f.txt\"]})
   => (ok [\"sd\" \"--\" \"\\\\d+\" \"N\" \"f.txt\"])

   (argv :grep [:+ [:class [\\0 \\9]]] {:operands [\"src\"]})
   => (ok [\"grep\" \"-E\" \"-e\" \"[0-9]+\" \"--\" \"src\"])"
  ([tool-id form] (argv tool-id form {}))
  ([tool-id form {:keys [flags operands]}]
   (r/let-ok [t    (tool tool-id)
              expr (api/->expr (:tool/dialect t) form)]
     (let [sep          (:tool/separator t)
           pattern-flag (:tool/flag t)]
       (r/ok (into []
                   cat
                   (if pattern-flag
                     [[(:tool/bin t)]
                      (vec (:tool/dialect-flags t))
                      (vec flags)
                      [pattern-flag expr]
                      (when (and sep (seq operands)) [sep])
                      (vec operands)]
                     [[(:tool/bin t)]
                      (vec (:tool/dialect-flags t))
                      (vec flags)
                      (when sep [sep])
                      [expr]
                      (vec operands)])))))))

(defn executable
  "Result<string>: the name TOOL-ID is actually installed under HERE.

   `:tool/bin` is the canonical name and the one `argv` emits, because an argv
   is a claim about a program's GRAMMAR and that claim does not change with
   packaging. argv[0] does: Debian ships fd as `fdfind`, so the canonical name
   resolves to nothing and the argv `argv` built is correct and unrunnable.

   Tries `:tool/bin` first, then `:tool/bin-alts` in order, and refuses naming
   every name it tried — rather than letting the caller meet it as an ENOENT
   from the fork."
  [tool-id]
  (r/let-ok [t (tool tool-id)]
    (let [names (into [(:tool/bin t)] (:tool/bin-alts t))]
      (or (some (fn [n] (when (r/ok? (detect/which n)) (r/ok n))) names)
          (r/err :search/tool-not-installed {:id tool-id :tried names})))))

(m/=> executable [:=> [:cat :keyword] :any])

(defn spawn-argv
  "Result<vector<string>>: `argv`, with argv[0] resolved against PATH — the
   argv to actually spawn.

   Two refusals, both before the fork: the dialect cannot express the construct
   (`:construct/unsupported`), or the program is not installed under any name
   it goes by (`:search/tool-not-installed`).

   The construct is checked FIRST, deliberately. That refusal is a fact about
   the command line and reads the same on every machine; the PATH one is a fact
   about this host. Resolving first would let the same call fail two different
   ways depending on what happens to be installed.

   Use `argv` to reason about the command line, this to run it."
  ([tool-id form] (spawn-argv tool-id form {}))
  ([tool-id form opts]
   (r/let-ok [args (argv tool-id form opts)
              bin  (executable tool-id)]
     (r/ok (assoc args 0 bin)))))

(m/=> spawn-argv [:function
                  [:=> [:cat :keyword :any] :any]
                  [:=> [:cat :keyword :any [:maybe :map]] :any]])

(m/=> argv [:function
            [:=> [:cat :keyword :any] :any]
            [:=> [:cat :keyword :any [:maybe :map]] :any]])

(defn runnable?
  "Result<boolean>: can TOOL-ID's dialect express FORM? Answered from the
   shape — nothing is compiled and nothing is spawned."
  [tool-id form]
  (r/let-ok [t (tool tool-id)]
    (api/supported? (:tool/dialect t) form)))

(defn explain
  "Result<map>: what FORM requires, and which registered TOOLS can run it.
   `:runnable` is the subset whose dialect covers the construct; `:blocked`
   maps the rest to the capabilities they lack."
  [form]
  (r/let-ok [detail (api/explain form)]
    (let [per-dialect (:dialects detail)
          by-tool     (into (sorted-map)
                            (map (fn [[id t]]
                                   [id (get per-dialect (:tool/dialect t) [])]))
                            @tools*)]
      (r/ok (assoc detail
                   :runnable (into (sorted-set)
                                   (keep (fn [[id missing]] (when (empty? missing) id)))
                                   by-tool)
                   :blocked  (into (sorted-map)
                                   (remove (comp empty? val))
                                   by-tool))))))
