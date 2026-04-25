(ns hive-system.secrets.registry-test
  "Tests for the backend registry + uniform fetch API."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-dsl.result :as r]
            [hive-system.secrets.core :as sec :refer [expose]]
            [hive-system.secrets.protocols :as proto]
            [hive-system.secrets.registry :as reg]))

;; =============================================================================
;; Test fixture: snapshot + restore the backend registry around each test
;; (Per the hive-mcp test-isolation axiom: never leak global state across tests.)
;; =============================================================================

(use-fixtures :each
  (fn [f]
    (let [snapshot (reg/registered)]
      (try
        (doseq [id (keys snapshot)] (reg/unregister! id))
        (f)
        (finally
          ;; Restore exactly what was registered before
          (doseq [id (keys (reg/registered))] (reg/unregister! id))
          (doseq [b (vals snapshot)] (reg/register! b)))))))

;; =============================================================================
;; Mock backend
;; =============================================================================

(defrecord MockBackend [id-key responses]
  proto/ISecretBackend
  (backend-id [_] id-key)
  (fetch [_ key _opts]
    (if-let [v (get responses key)]
      (r/ok (sec/make-secret v id-key key))
      (r/err :mock/not-found {:key key})))
  (available? [_] (r/ok true)))

;; =============================================================================
;; register! / unregister! / registered
;; =============================================================================

(deftest register-and-lookup
  (testing "register! makes a backend retrievable by id"
    (let [b (->MockBackend :mock {})]
      (reg/register! b)
      (let [result (reg/backend :mock)]
        (is (r/ok? result))
        (is (= b (:ok result)))))))

(deftest unknown-backend
  (testing "looking up an unregistered id returns err"
    (let [result (reg/backend :nonexistent)]
      (is (r/err? result))
      (is (= :secrets/unknown-backend (:error result))))))

(deftest unregister-removes
  (testing "unregister! removes the backend"
    (reg/register! (->MockBackend :mock {}))
    (reg/unregister! :mock)
    (is (r/err? (reg/backend :mock)))))

(deftest registered-snapshot
  (testing "registered returns a map of all backends"
    (reg/register! (->MockBackend :a {}))
    (reg/register! (->MockBackend :b {}))
    (is (= #{:a :b} (set (keys (reg/registered)))))))

;; =============================================================================
;; validate-ref
;; =============================================================================

(deftest validate-ref-happy
  (is (r/ok? (reg/validate-ref {:backend :pass :key "x"})))
  (is (r/ok? (reg/validate-ref {:backend :pass :key "x" :opts {}}))))

(deftest validate-ref-missing-backend
  (let [result (reg/validate-ref {:key "x"})]
    (is (r/err? result))
    (is (= :secrets/invalid-ref (:error result)))))

(deftest validate-ref-non-string-key
  (let [result (reg/validate-ref {:backend :pass :key 42})]
    (is (r/err? result))))

(deftest validate-ref-non-map-opts
  (let [result (reg/validate-ref {:backend :pass :key "x" :opts "bad"})]
    (is (r/err? result))))

;; =============================================================================
;; fetch — end-to-end
;; =============================================================================

(deftest fetch-resolves
  (testing "fetch dispatches to the correct backend and returns Secret"
    (reg/register! (->MockBackend :mock {"vps/r1/root" "TOPSECRET"}))
    (let [result (reg/fetch {:backend :mock :key "vps/r1/root"})]
      (is (r/ok? result))
      (is (sec/secret? (:ok result)))
      (is (= "TOPSECRET" (expose (:ok result)))))))

(deftest fetch-unknown-backend
  (testing "fetch with unregistered backend returns err"
    (let [result (reg/fetch {:backend :nope :key "x"})]
      (is (r/err? result))
      (is (= :secrets/unknown-backend (:error result))))))

(deftest fetch-invalid-ref
  (testing "fetch with invalid ref returns err before touching backend"
    (let [result (reg/fetch {:key "x"})]
      (is (r/err? result))
      (is (= :secrets/invalid-ref (:error result))))))

(deftest fetch-backend-err-propagates
  (testing "backend err propagates as-is"
    (reg/register! (->MockBackend :mock {}))
    (let [result (reg/fetch {:backend :mock :key "missing"})]
      (is (r/err? result))
      (is (= :mock/not-found (:error result))))))
