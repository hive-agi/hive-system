(ns hive-system.protocols.gpu
  "GPU executor protocols — DIP boundary for GPU-bound work.

   Two protocols, ISP-split:
     IGpuExecutor  — does work (embed, generate, rerank)
     IGpuStatus    — introspects backend (free VRAM, inflight, queued)

   Closed ADTs cross the boundary:
     GpuRequest    — what the caller wants done + declared :gpu/vram-mb budget
     GpuResponse   — output payload + executor-id + duration-ms

   Layering rationale:
     hive-mcp consumers (embedders, future rerankers, future local-LLM
     compression) depend on these protocols, never on a concrete backend.
     hive-weave.gpu admits requests against a VRAM budget BEFORE dispatching
     through gpu-execute!. New backends (ollama, llama.cpp, vLLM) extend the
     protocols; admission control + consumers stay closed (OCP).

   CPPB mapping:
     Promote   — GpuRequest is the ADT shape callers build up
     Pipeline  — hive-weave.gpu/gpu-fork-join admits + dispatches
     Boundary  — concrete IGpuExecutor impl performs IO

   SOLID:
     SRP — IGpuExecutor does work; IGpuStatus introspects; admission lives in hive-weave
     OCP — new backends extend; consumers + admission untouched
     LSP — every executor returns the same Result shape (see schemas below)
     ISP — split work vs introspection so a probe-only sidecar (nvidia-smi)
           can satisfy IGpuStatus without claiming work-execution capability
     DIP — every consumer depends on these protocols, never on a record")

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; =============================================================================
;; GpuRequest — closed ADT
;; =============================================================================
;;
;; Shape:
;;   {:gpu/op        keyword        ; one of #{:embed :generate :rerank}
;;    :gpu/vram-mb   pos-int        ; declared budget the caller estimates
;;    :gpu/payload   map            ; op-specific payload (see below)
;;    :gpu/timeout-ms int (optional)
;;    :gpu/model      string (optional, executor-specific)}
;;
;; Per-op :gpu/payload:
;;   :embed     -> {:text string} OR {:texts [string ...]}
;;   :generate  -> {:prompt string :max-tokens int}
;;   :rerank    -> {:query string :candidates [string ...] :top-k int}
;;
;; The closed-ADT contract: callers MUST NOT add ad-hoc keys; executors MUST
;; reject unknown :gpu/op via (err :gpu/unsupported-op ...).

;; =============================================================================
;; GpuResponse — closed ADT (the ok-branch payload)
;; =============================================================================
;;
;; Shape:
;;   {:gpu/executor-id keyword       ; e.g. :ollama, :llama-cpp, :vllm
;;    :gpu/op          keyword       ; echo of request :gpu/op
;;    :gpu/duration-ms long          ; wall-clock for the gpu-execute! call
;;    :gpu/output      map}          ; op-specific (see below)
;;
;; Per-op :gpu/output:
;;   :embed     -> {:vectors [[float ...] ...] :dim int}
;;   :generate  -> {:text string :tokens-out int :stop-reason keyword}
;;   :rerank    -> {:scores [float ...] :order [int ...]}
;;
;; Err branch carries:
;;   {:gpu/op keyword :gpu/cause any :gpu/executor-id keyword?}
;; with err-tag drawn from:
;;   :gpu/unsupported-op :gpu/timeout :gpu/oom :gpu/transport-failed
;;   :gpu/payload-invalid :gpu/no-driver :gpu/over-budget

;; =============================================================================
;; IGpuExecutor — work
;; =============================================================================

(defprotocol IGpuExecutor
  "Executes GPU work. Concretions: ollama HTTP, llama.cpp, vLLM, raw CUDA.

   Every method returns Result (ok/err) from hive-dsl.result. No exceptions
   cross the boundary; transport failures classify as :gpu/transport-failed,
   payload mismatches as :gpu/payload-invalid, etc."
  (gpu-execute! [this request]
    "Execute a GpuRequest. Returns Result<GpuResponse>.
     Implementations dispatch by (:gpu/op request) and MUST emit
     (err :gpu/unsupported-op ...) for ops outside executor-capabilities.")

  (executor-id [this]
    "Stable keyword identifying this executor (e.g. :ollama, :llama-cpp).
     Used by callers for routing and by hive-weave admission for telemetry.")

  (executor-capabilities [this]
    "Set of supported :gpu/op keywords, drawn from #{:embed :generate :rerank}.
     Pure introspection — no IO."))

;; =============================================================================
;; IGpuStatus — introspection
;; =============================================================================

(defprotocol IGpuStatus
  "Introspects a GPU backend's resource state. Sibling to IGpuExecutor; an
   nvidia-smi probe satisfies IGpuStatus without claiming IGpuExecutor.

   ISP rationale: an admission scheduler reads status to decide; it does NOT
   need the ability to run work. A probe satisfies status; a concrete
   executor satisfies both (its status snapshot draws on its own counters)."
  (gpu-status [this]
    "Snapshot of backend state. Returns Result<map> with at least:
       {:vram-free-mb   long
        :vram-total-mb  long
        :inflight       long       ; in-flight gpu-execute! calls
        :queued         long       ; admission-queued tasks
        :backend-id     keyword}   ; e.g. :nvidia-smi, :ollama
     Probes that cannot read all fields MAY return -1 for unknowns rather
     than err, so callers can distinguish 'unknown' from 'no driver'."))
