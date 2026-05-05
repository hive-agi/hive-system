(ns hive-system.gpu.executor-property-test
  "LSP contract suite for IGpuExecutor impls.

   Any executor (mock, ollama, future llama-cpp/vLLM) MUST satisfy:
   1. executor-id returns a non-nil keyword
   2. executor-capabilities returns a subset of #{:embed :generate :rerank}
   3. gpu-execute! on a supported op returns Result with the documented shape
   4. gpu-execute! on an unsupported op returns (err :gpu/unsupported-op ...)
   5. ok-branch payload preserves :gpu/op, has :gpu/executor-id, :gpu/duration-ms

   Mock executor satisfies these; ollama executor satisfies these (live, gated
   by HIVE_GPU_E2E=1 env)."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive-dsl.result :as r]
            [hive-system.protocols.gpu :as gpu]
            [hive-system.gpu.ollama :as ollama]))

;; =============================================================================
;; Mock executor — satisfies the contract deterministically
;; =============================================================================

(defrecord MockGpuExecutor [executor-id-key caps]
  gpu/IGpuExecutor
  (gpu-execute! [_ request]
    (let [op (:gpu/op request)]
      (if (contains? caps op)
        (r/ok {:gpu/executor-id executor-id-key
               :gpu/op          op
               :gpu/duration-ms 1
               :gpu/output      (case op
                                  :embed    {:vectors [[0.0 0.1 0.2]] :dim 3}
                                  :generate {:text "mock" :tokens-out 1 :stop-reason :stop}
                                  :rerank   {:scores [1.0] :order [0]})})
        (r/err :gpu/unsupported-op
               {:gpu/op op :gpu/executor-id executor-id-key}))))
  (executor-id [_] executor-id-key)
  (executor-capabilities [_] caps))

(defn mk-mock
  ([] (mk-mock #{:embed :generate :rerank}))
  ([caps] (->MockGpuExecutor :mock caps)))

;; =============================================================================
;; LSP contract assertions (reusable across executors)
;; =============================================================================

(defn assert-executor-contract
  "Run the LSP contract against any IGpuExecutor impl. `op` is one of the
   capabilities the executor declares; `payload` is op-appropriate."
  [executor op payload]
  (let [resp (gpu/gpu-execute! executor
                               {:gpu/op       op
                                :gpu/vram-mb  100
                                :gpu/payload  payload})]
    (is (map? resp) "Result must be a map")
    (when (r/ok? resp)
      (let [out (:ok resp)]
        (is (= op (:gpu/op out)) "ok-branch echoes :gpu/op")
        (is (some? (:gpu/executor-id out)) "ok-branch carries :gpu/executor-id")
        (is (number? (:gpu/duration-ms out)) "ok-branch carries numeric :gpu/duration-ms")
        (is (map? (:gpu/output out)) "ok-branch :gpu/output is a map")))
    resp))

;; =============================================================================
;; Mock executor contract tests
;; =============================================================================

(deftest mock-satisfies-protocols
  (let [m (mk-mock)]
    (is (satisfies? gpu/IGpuExecutor m))
    (is (keyword? (gpu/executor-id m)))
    (is (set? (gpu/executor-capabilities m)))
    (is (every? #{:embed :generate :rerank} (gpu/executor-capabilities m)))))

(deftest mock-supported-op-returns-ok
  (testing ":embed returns ok with :vectors + :dim"
    (let [resp (assert-executor-contract (mk-mock) :embed {:text "hi"})]
      (is (r/ok? resp))
      (let [out (-> resp :ok :gpu/output)]
        (is (vector? (:vectors out)))
        (is (pos-int? (:dim out)))))))

(deftest mock-unsupported-op-returns-err
  (let [m    (mk-mock #{:embed})        ; no :generate
        resp (gpu/gpu-execute! m {:gpu/op :generate :gpu/vram-mb 100 :gpu/payload {:prompt "x"}})]
    (is (r/err? resp))
    (is (= :gpu/unsupported-op (:error resp)))))

;; =============================================================================
;; Property: ok-branch shape is preserved across random capability selections
;; =============================================================================

(def ^:private op-payload
  {:embed    {:text "hello"}
   :generate {:prompt "hi" :max-tokens 1}
   :rerank   {:query "q" :candidates ["a" "b"] :top-k 1}})

(defspec mock-ok-shape-property 50
  (prop/for-all [op (gen/elements [:embed :generate :rerank])]
    (let [m    (mk-mock #{op})
          resp (gpu/gpu-execute! m {:gpu/op op :gpu/vram-mb 100 :gpu/payload (op-payload op)})]
      (and (r/ok? resp)
           (= op (-> resp :ok :gpu/op))
           (some? (-> resp :ok :gpu/executor-id))
           (number? (-> resp :ok :gpu/duration-ms))
           (map? (-> resp :ok :gpu/output))))))

(defspec mock-err-shape-on-unsupported 50
  (prop/for-all [available (gen/elements [#{:embed} #{:generate} #{:rerank}
                                          #{:embed :generate} #{:embed :rerank}])
                 requested (gen/elements [:embed :generate :rerank])]
    (let [m    (mk-mock available)
          resp (gpu/gpu-execute! m {:gpu/op requested :gpu/vram-mb 100
                                     :gpu/payload (op-payload requested)})]
      (if (contains? available requested)
        (r/ok? resp)
        (and (r/err? resp) (= :gpu/unsupported-op (:error resp)))))))

;; =============================================================================
;; Live ollama contract test — gated by env
;; =============================================================================

(deftest ollama-satisfies-contract
  (let [exec (ollama/ollama-executor)]
    (is (satisfies? gpu/IGpuExecutor exec))
    (is (satisfies? gpu/IGpuStatus exec))
    (is (= :ollama (gpu/executor-id exec)))
    (is (= #{:embed :generate} (gpu/executor-capabilities exec)))))

(deftest ollama-embed-e2e
  (testing "Ollama embed end-to-end (set HIVE_GPU_E2E=1 to enable)"
    (when (= "1" (System/getenv "HIVE_GPU_E2E"))
      (let [exec (ollama/ollama-executor)
            resp (assert-executor-contract exec :embed {:text "test sentence"})]
        (is (r/ok? resp))
        (when (r/ok? resp)
          (let [out (-> resp :ok :gpu/output)]
            (is (pos-int? (:dim out)))
            (is (= 1 (count (:vectors out))))))))))
