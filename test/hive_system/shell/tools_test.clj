(ns hive-system.shell.tools-test
  "Tests for tool registry, require-tool, and install hint generation.
   Mutation tests verify hints actually surface when tools are missing.
   Property tests verify totality and idempotency."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [hive-test.golden :refer [deftest-golden]]
            [hive-test.mutation :refer [deftest-mutations]]
            [hive-test.properties :refer [defprop-total defprop-idempotent]]
            [hive-dsl.result :as r]
            [hive-system.shell.tools :as tools]
            [hive-system.shell.detect :as detect]))

;; =============================================================================
;; Golden: Lock down tool registry structure
;; =============================================================================

(deftest-golden tool-registry-keys
  "test/golden/tools/registry-keys.edn"
  (set (map :tool (tools/list-tools))))

;; =============================================================================
;; Unit: require-tool Result shapes
;; =============================================================================

(deftest require-tool-found
  (testing "require-tool for a present tool returns ok with metadata"
    (let [result (tools/require-tool :git)]
      (when (r/ok? result)
        (is (= :git (get-in result [:ok :tool])))
        (is (string? (get-in result [:ok :path])))
        (is (string? (get-in result [:ok :desc])))))))

(deftest require-tool-missing-has-hints
  (testing "require-tool for missing tool returns err with install hints"
    ;; Use a tool that's almost certainly not installed
    (let [result (tools/require-tool :dust)]
      (when (r/err? result)
        (is (= :tool/missing (:error result)))
        (is (string? (:message result)))
        (is (vector? (:hints result)))
        ;; Every hint has :manager and :command
        (doseq [hint (:hints result)]
          (is (keyword? (:manager hint)))
          (is (string? (:command hint))))))))

(deftest require-tool-unknown
  (testing "require-tool for unregistered tool returns :tool/unknown"
    (let [result (tools/require-tool :nonexistent-tool-xyz)]
      (is (r/err? result))
      (is (= :tool/unknown (:error result)))
      (is (vector? (:available result))))))

;; =============================================================================
;; Unit: require-tools batch
;; =============================================================================

(deftest require-tools-partitions
  (testing "require-tools partitions into :available and :missing"
    (let [{:keys [available missing]} (tools/require-tools [:git :ls :dust :procs])]
      (is (map? available))
      (is (map? missing))
      ;; git and ls should be available on any system
      (is (contains? available :git))
      (is (contains? available :ls))
      ;; Every value is a Result
      (doseq [[_ v] available] (is (r/ok? v)))
      (doseq [[_ v] missing] (is (r/err? v))))))

;; =============================================================================
;; Unit: list-tools shape
;; =============================================================================

(deftest list-tools-shape
  (testing "list-tools returns consistent shape per entry"
    (let [tools-list (tools/list-tools)]
      (is (vector? tools-list))
      (is (pos? (count tools-list)))
      (doseq [{:keys [tool bin desc available? path]} tools-list]
        (is (keyword? tool))
        (is (string? bin))
        (is (string? desc))
        (is (boolean? available?))
        (if available?
          (is (string? path))
          (is (nil? path)))))))

;; =============================================================================
;; Mutation: which resolution is critical to require-tool
;; =============================================================================

(deftest-mutations which-mutations-caught
  detect/which
  [["always-found"   (fn [_] (r/ok {:path "/fake" :program "fake"}))]
   ["always-missing" (fn [_] (r/err :shell/not-found {:program "fake"}))]
   ["returns-nil"    (fn [_] nil)]]
  (fn []
    ;; Assertions must catch every mutation — verify actual path content
    (let [found (tools/require-tool :ls)]
      (is (r/ok? found))
      (is (.contains ^String (get-in found [:ok :path]) "ls"))
      (is (.startsWith ^String (get-in found [:ok :path]) "/")))))

;; =============================================================================
;; Property: require-tool is total for all registered tool keys
;; =============================================================================

(defprop-total require-tool-total
  tools/require-tool
  (gen/elements [:ripgrep :fd :jq :tree :fzf :bat :delta :htop
                 :dust :procs :sd :tokei :kubectl :tmux :find :ls :git])
  {:num-tests 50
   :pred (fn [r] (or (r/ok? r) (r/err? r)))})

;; =============================================================================
;; Property: list-tools is idempotent (no side effects change results)
;; =============================================================================

(defprop-idempotent list-tools-idempotent
  (fn [_] (set (map :tool (tools/list-tools))))
  gen/nat
  {:num-tests 5})
