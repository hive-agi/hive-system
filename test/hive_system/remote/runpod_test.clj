(ns hive-system.remote.runpod-test
  "The RunPod IHostProvider over a stub :http and a manual :schedule. No
   network, no billable resource, no sleeping."
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.runpod :as runpod]
            [clojure.string :as str]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:private spec {:name "w" :gpu-type "NVIDIA A40" :gpu-count 2 :max-usd-per-hr 1.0 :ttl-ms 3600000})

(def ^:private catalog [{:id "NVIDIA A40" :price {:secure 0.44 :community 0.35}}])

(defn- fake-http
  "Stub v2 API. `pod-bodies` is a seq of GET /pods/:id answers, consumed in order."
  [calls {:keys [catalog created pod-bodies terminate]
          :or   {catalog catalog created {:id "p1" :cost 0.88}
                 pod-bodies [{:id "p1" :ssh {:direct {:host "1.2.3.4" :port 40022 :username "root"}}}]
                 terminate (r/ok {})}}]
  (let [bodies (atom pod-bodies)]
    (fn [{:keys [method path] :as req}]
      (swap! calls conj (select-keys req [:method :path :body]))
      (cond
        (= path "/catalog/gpus")               (r/ok catalog)
        (and (= :post method) (= path "/pods")) (if (r/err? created) created (r/ok created))
        (str/ends-with? path "/action")        terminate
        :else (let [b (first @bodies)] (when (next @bodies) (swap! bodies rest)) (r/ok b))))))

(defn- manual-schedule
  "A :schedule that records [ms f] and runs nothing; cancel marks it."
  [scheduled]
  (fn [ms f]
    (let [i (count @scheduled)]
      (swap! scheduled conj {:ms ms :f f :cancelled? false})
      (fn [] (swap! scheduled assoc-in [i :cancelled?] true)))))

(def ^:private shell
  (reify proto/IShell
    (shell-exec! [_ _ _] (r/ok {:exit 0 :stdout "" :stderr "" :duration-ms 1.0}))
    (shell-env [_] {})
    (shell-which [_ p] (r/ok {:path p}))))

(def ^:private process
  (reify proto/IProcess
    (process-spawn! [_ cmd _] (r/ok {:pid 1 :cmd cmd}))
    (process-wait! [_ _ _] (r/ok {:exit-code 0}))
    (process-signal! [_ _ _] (r/ok {:delivered? true}))
    (process-pipe! [_ _ _] (r/ok {}))))

(defn- provider [calls scheduled opts]
  (:ok (ports/host-provider {:kind :runpod :shell shell :process process :poll-ms 10
                             :http (fake-http calls opts) :schedule (manual-schedule scheduled)
                             :sleep! (fn [_] nil)})))

(defn- terminations [calls] (filterv #(= {:action "terminate"} (:body %)) @calls))

(deftest pod-request-always-exposes-ssh
  (is (= {:name "w" :image runpod/default-image :cloud "SECURE" :gpu {:id "NVIDIA A40" :count 2}
          :ports ["22/tcp" "8888/http"]}
         (runpod/pod-request (assoc spec :ports ["8888/http" "22/tcp"])))))

(deftest spec-without-limits-is-refused-before-any-request
  (let [calls (atom [])]
    (doseq [s [(dissoc spec :max-usd-per-hr) (dissoc spec :ttl-ms)]]
      (is (= :remote/invalid-spec (:error (ports/provision! (provider calls (atom []) {}) s)))))
    (is (empty? @calls))))

(deftest catalog-price-over-cap-never-creates
  (let [calls (atom [])
        res   (ports/provision! (provider calls (atom []) {}) (assoc spec :max-usd-per-hr 0.5))]
    (is (= :remote/over-spend-cap (:error res)))
    (is (= 0.88 (:price-usd-per-hr res)))
    (is (not-any? #(= :post (:method %)) @calls))))

(deftest unpriced-gpu-never-creates
  (is (= :remote/unpriced (:error (ports/provision! (provider (atom []) (atom []) {}) (assoc spec :gpu-type "H200"))))))

(deftest happy-path-answers-an-ssh-host-and-arms-the-ttl
  (let [calls (atom []) scheduled (atom [])
        prov  (provider calls scheduled
                        {:pod-bodies [{:id "p1"} {:id "p1" :ssh {:direct {:host "1.2.3.4" :port 40022}}}]})
        res   (ports/provision! prov spec)]
    (is (= "p1" (:id (:ok res))))
    (is (= {:host "1.2.3.4" :port 40022 :user "root" :options {"StrictHostKeyChecking" "accept-new"}}
           (:target (:host (:ok res)))))
    (is (= [{:ms 3600000 :cancelled? false}] (mapv #(dissoc % :f) @scheduled)))
    (testing "terminate cancels the TTL and calls the API; again is fine"
      (is (r/ok? (ports/terminate! prov "p1")))
      (is (:cancelled? (first @scheduled)))
      (is (r/ok? (ports/terminate! prov "p1")))
      (is (= 2 (count (terminations calls)))))))

(deftest ttl-fires-a-terminate
  (let [calls (atom []) scheduled (atom [])]
    (ports/provision! (provider calls scheduled {}) spec)
    ((:f (first @scheduled)))
    (is (= [{:method :post :path "/pods/p1/action" :body {:action "terminate"}}] (terminations calls)))))

(deftest created-pod-over-cap-is-terminated-at-once
  (let [calls (atom []) scheduled (atom [])
        res   (ports/provision! (provider calls scheduled {:created {:id "p1" :cost 5.0}}) spec)]
    (is (= :remote/over-spend-cap (:error res)))
    (is (true? (:terminated? res)))
    (is (= 1 (count (terminations calls))))
    (is (:cancelled? (first @scheduled)))))

(deftest pod-never-ready-is-terminated
  (let [calls (atom [])
        res   (ports/provision! (provider calls (atom []) {:pod-bodies [{:id "p1"}]})
                                (assoc spec :ready-timeout-ms 30))]
    (is (= :remote/pod-not-ready (:error res)))
    (is (= 1 (count (terminations calls))))))

(deftest terminate-of-a-gone-pod-is-ok
  (let [prov (provider (atom []) (atom []) {:terminate (r/err :remote/not-found {})})]
    (is (true? (:already-gone? (:ok (ports/terminate! prov "gone")))))))

(deftest with-host-terminates-a-runpod-host
  (let [calls (atom [])]
    (is (= (r/ok :ran) (ports/with-host (provider calls (atom []) {}) spec (fn [_] (r/ok :ran)))))
    (is (= 1 (count (terminations calls))))))

(deftest live-caller-without-a-key-is-an-err-not-a-request
  (is (= :remote/credentials-missing
         (:error ((runpod/http-caller {:api-key-env "HIVE_SYSTEM_TEST_NO_SUCH_VAR"}) {:method :get :path "/pods"})))))
