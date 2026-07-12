(ns hive-system.gpu.probe
  "nvidia-smi probe satisfying IGpuStatus.

   Authoritative source for VRAM observability. The OllamaGpuExecutor's
   gpu-status returns -1 for VRAM fields because ollama doesn't expose them
   reliably; this probe shells out to nvidia-smi for the truth.

   Uses hive-system.protocols/IShell so a mock shell can drive tests
   without launching real subprocesses (DIP). Default ctor wires the
   stateless hive-system.shell.core/exec! convenience.

   Output schema (ok branch):
     {:vram-free-mb  long
      :vram-total-mb long
      :inflight      0          ; probe doesn't track in-flight calls
      :queued        0          ; idem
      :backend-id    :nvidia-smi}

   Err branch tags:
     :gpu/no-driver       — nvidia-smi missing on PATH or returned non-zero
     :gpu/probe-parse     — nvidia-smi output couldn't be parsed
     :gpu/transport-failed — exec layer raised"
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as sys-proto]
            [hive-system.protocols.gpu :as gpu]
            [hive-system.shell.core :as shell]
            [taoensso.timbre :as log]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; =============================================================================
;; Parsing
;; =============================================================================

(defn parse-csv-line
  "Parse one CSV line of `<free>, <total>` integer MiB values."
  [^String line]
  (let [parts (->> (str/split line #",")
                   (mapv str/trim)
                   (remove str/blank?))]
    (when (= 2 (count parts))
      (try
        {:vram-free-mb  (parse-long (first parts))
         :vram-total-mb (parse-long (second parts))}
        (catch NumberFormatException _ nil)))))

(defn parse-nvidia-smi-csv
  "Parse stdout of `nvidia-smi --query-gpu=memory.free,memory.total --format=csv,noheader,nounits`.
   Single-GPU host: returns the first parsed line. Multi-GPU: same — for
   v1 we surface the first card; the probe can be parameterised later."
  [^String stdout]
  (some-> (->> (str/split-lines stdout)
               (map str/trim)
               (remove str/blank?)
               first)
          parse-csv-line))

;; =============================================================================
;; Probe record
;; =============================================================================

(defrecord NvidiaSmiProbe
  [shell command timeout-ms]
  gpu/IGpuStatus
  (gpu-status [_]
    (let [exec-result (sys-proto/shell-exec! shell command {:timeout-ms timeout-ms})]
      (cond
        (r/err? exec-result)
        (r/err :gpu/transport-failed
               {:gpu/cause       (:error exec-result)
                :gpu/executor-id :nvidia-smi})

        :else
        (let [{:keys [exit stdout stderr]} (or (:ok exec-result) exec-result)]
          (cond
            (not (zero? (or exit -1)))
            (r/err :gpu/no-driver
                   {:exit            exit
                    :stderr          (some-> stderr str/trim)
                    :hint            "nvidia-smi missing or returned non-zero"
                    :gpu/executor-id :nvidia-smi})

            :else
            (if-let [parsed (parse-nvidia-smi-csv (or stdout ""))]
              (r/ok (merge parsed
                           {:inflight   0
                            :queued     0
                            :backend-id :nvidia-smi}))
              (r/err :gpu/probe-parse
                     {:stdout          stdout
                      :gpu/executor-id :nvidia-smi
                      :hint            "nvidia-smi stdout did not match expected CSV shape"}))))))))

;; =============================================================================
;; Public constructor
;; =============================================================================

(def ^:private default-cmd
  ["nvidia-smi"
   "--query-gpu=memory.free,memory.total"
   "--format=csv,noheader,nounits"])

(defn nvidia-smi-probe
  "Build an NvidiaSmiProbe.

   Options:
     :shell      — IShell impl (default: hive-system.shell.core/make-shell)
     :command    — argv vector (default: nvidia-smi memory.free,memory.total CSV)
     :timeout-ms — exec timeout (default 5000)"
  ([] (nvidia-smi-probe {}))
  ([{:keys [shell command timeout-ms]
     :or   {shell      (shell/make-shell)
            command    default-cmd
            timeout-ms 5000}}]
   (->NvidiaSmiProbe shell command timeout-ms)))
