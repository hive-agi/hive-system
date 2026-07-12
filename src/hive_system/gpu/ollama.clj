(ns hive-system.gpu.ollama
  "OllamaGpuExecutor — IGpuExecutor + IGpuStatus over the ollama HTTP API.

   First concretion of hive-system.protocols.gpu. Mirrors hive-system.secrets/*
   placement: protocol in hive-system.protocols.*, concrete adapter in a
   sibling sub-namespace.

   Capabilities:
     :embed     — POST /api/embed
     :generate  — POST /api/generate (single-shot, no streaming for now)

   What we deliberately don't do here:
     - Pool / retry classification — that's the caller's job via
       hive-weave.gpu/gpu-fork-join + hive-dsl rescue helpers.
     - Streaming / SSE — generate returns once, no incremental delta.
     - Model autoload — assumes `ollama pull <model>` already happened.

   Construct via (->ollama-executor opts) — never the raw record ctor."
  (:require [clojure.data.json :as json]
            [hive-dsl.result :as r]
            [hive-system.protocols.gpu :as gpu]
            [taoensso.timbre :as log])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.time Duration]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; =============================================================================
;; HTTP plumbing (private)
;; =============================================================================

(defn- mk-http-client
  ^HttpClient [^long connect-timeout-ms]
  (-> (HttpClient/newBuilder)
      (.connectTimeout (Duration/ofMillis connect-timeout-ms))
      (.build)))

(defn- post-json!
  "POST JSON payload to (str host endpoint). Returns parsed body map.
   Throws ex-info on non-200."
  [^HttpClient client host endpoint payload timeout-ms]
  (let [url      (str host endpoint)
        request  (-> (HttpRequest/newBuilder)
                     (.uri (URI/create url))
                     (.header "Content-Type" "application/json")
                     (.POST (HttpRequest$BodyPublishers/ofString
                              (json/write-str payload)))
                     (.timeout (Duration/ofMillis timeout-ms))
                     (.build))
        response (.send client request (HttpResponse$BodyHandlers/ofString))
        status   (.statusCode response)
        body     (.body response)]
    (if (= 200 status)
      (json/read-str body :key-fn keyword)
      (throw (ex-info "Ollama HTTP non-200"
                      {:status status :body body :url url})))))

;; =============================================================================
;; Op handlers
;; =============================================================================

(defn- handle-embed
  [client host model timeout-ms payload]
  (let [text-or-texts (or (:texts payload) (:text payload))
        inputs        (if (sequential? text-or-texts) text-or-texts [text-or-texts])
        body          {:model      model
                       :input      (if (= 1 (count inputs)) (first inputs) inputs)
                       :keep_alive "24h"
                       :options    {:num_ctx 8192}}
        resp          (post-json! client host "/api/embed" body timeout-ms)
        vectors       (mapv vec (:embeddings resp))]
    {:vectors vectors
     :dim     (count (first vectors))}))

(defn- handle-generate
  [client host model timeout-ms payload]
  (let [body {:model      model
              :prompt     (:prompt payload)
              :stream     false
              :keep_alive "24h"
              :options    (cond-> {}
                            (:max-tokens payload) (assoc :num_predict (:max-tokens payload)))}
        resp (post-json! client host "/api/generate" body timeout-ms)]
    {:text        (:response resp)
     :tokens-out  (or (:eval_count resp) -1)
     :stop-reason (keyword (or (:done_reason resp) "unknown"))}))

;; =============================================================================
;; OllamaGpuExecutor record
;; =============================================================================

(defrecord OllamaGpuExecutor
  [executor-id-key host default-model default-timeout-ms ^HttpClient client]
  gpu/IGpuExecutor
  (gpu-execute! [this request]
    (let [op         (:gpu/op request)
          payload    (or (:gpu/payload request) {})
          model      (or (:gpu/model request) default-model)
          timeout-ms (or (:gpu/timeout-ms request) default-timeout-ms)
          start      (System/currentTimeMillis)]
      (try
        (let [output (case op
                       :embed    (handle-embed client host model timeout-ms payload)
                       :generate (handle-generate client host model timeout-ms payload)
                       (throw (ex-info "Unsupported op" {:gpu/op op})))]
          (r/ok {:gpu/executor-id executor-id-key
                 :gpu/op          op
                 :gpu/duration-ms (- (System/currentTimeMillis) start)
                 :gpu/output      output}))
        (catch clojure.lang.ExceptionInfo e
          (let [d (ex-data e)]
            (cond
              (= op (:gpu/op d))
              (r/err :gpu/unsupported-op
                     {:gpu/op op :gpu/executor-id executor-id-key})

              :else
              (r/err :gpu/transport-failed
                     {:gpu/op          op
                      :gpu/executor-id executor-id-key
                      :gpu/cause       (.getMessage e)
                      :http-status     (:status d)}))))
        (catch Exception e
          (log/warn e "OllamaGpuExecutor unexpected failure" {:op op})
          (r/err :gpu/transport-failed
                 {:gpu/op          op
                  :gpu/executor-id executor-id-key
                  :gpu/cause       (.getMessage e)})))))

  (executor-id [_]
    executor-id-key)

  (executor-capabilities [_]
    #{:embed :generate})

  gpu/IGpuStatus
  (gpu-status [_]
    ;; Ollama's /api/ps lists loaded models but does not report VRAM
    ;; precisely. Return -1 for vram-* fields; nvidia-smi probe
    ;; (hive-system.gpu.probe) is the authoritative source.
    (try
      (let [resp (post-json! client host "/api/ps" {} 5000)]
        (r/ok {:vram-free-mb  -1
               :vram-total-mb -1
               :inflight      0
               :queued        0
               :backend-id    executor-id-key
               :loaded-models (mapv :name (:models resp))}))
      (catch Exception e
        (r/err :gpu/transport-failed
               {:gpu/executor-id executor-id-key
                :gpu/cause       (.getMessage e)})))))

;; =============================================================================
;; Public constructor
;; =============================================================================

(defn ollama-executor
  "Build an OllamaGpuExecutor.

   Options:
     :host                — base URL (default \"http://localhost:11434\")
     :default-model       — model used when GpuRequest omits :gpu/model
                            (default \"nomic-embed-text\")
     :default-timeout-ms  — per-op HTTP timeout (default 120000)
     :connect-timeout-ms  — TCP connect timeout (default 30000)
     :executor-id         — keyword id (default :ollama)"
  ([] (ollama-executor {}))
  ([{:keys [host default-model default-timeout-ms connect-timeout-ms executor-id]
     :or   {host               "http://localhost:11434"
            default-model      "nomic-embed-text"
            default-timeout-ms 120000
            connect-timeout-ms 30000
            executor-id        :ollama}}]
   (->OllamaGpuExecutor executor-id host default-model default-timeout-ms
                        (mk-http-client connect-timeout-ms))))
