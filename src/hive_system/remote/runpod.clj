(ns hive-system.remote.runpod
  "IHostProvider renting RunPod pods over its REST v2 API, answering an ssh
   IRemoteHost on the pod's direct-TCP ssh port.

   Design (the money is the hard part, so it is enforced here, not by callers):
     - every spec MUST carry :max-usd-per-hr and :ttl-ms; provision! refuses a
       spec without them before any request is made;
     - the catalog price is checked BEFORE create (:remote/over-spend-cap);
       the price the created pod reports is checked AFTER, and a pod over the
       cap is terminated at once;
     - a pod that never exposes ssh within :ready-timeout-ms is terminated;
     - a TTL terminate is scheduled the moment a pod exists, so a caller that
       dies without with-host still stops billing at :ttl-ms. terminate!
       cancels it and is idempotent (a 404 is ok).

   The HTTP call is data in the record (`:http`, a fn of
   {:method :path :query :body} -> Result<parsed body>) and the scheduler is
   too (`:schedule`, (fn [ms f]) -> cancel fn), so tests never reach the
   network and never sleep. `http-caller` is the live one: java.net.http,
   key read per request from :api-key-env (default RUNPOD_API_KEY), never
   logged or returned."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.ssh :as ssh]
            [malli.core :as m]
            [taoensso.timbre :as log])
  (:import [java.net URI URLEncoder]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.time Duration]
           [java.util Timer TimerTask]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def default-base-url "https://api.runpod.io/v2")

(def default-image "runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404")

(def RunPodSpec
  "What to rent, and the two limits no pod is rented without."
  [:map
   [:name [:string {:min 1}]]
   [:gpu-type [:string {:min 1}]]
   [:max-usd-per-hr [:and number? [:> 0]]]
   [:ttl-ms [:int {:min 1}]]
   [:gpu-count {:optional true} [:int {:min 1}]]
   [:image {:optional true} [:string {:min 1}]]
   [:cloud {:optional true} [:enum :secure :community]]
   [:data-centers {:optional true} [:vector :string]]
   [:disk-gb {:optional true} [:int {:min 1}]]
   [:volume-gb {:optional true} [:int {:min 1}]]
   [:volume-path {:optional true} :string]
   [:ports {:optional true} [:vector :string]]
   [:env {:optional true} [:map-of :string :string]]
   [:min-cuda {:optional true} :string]
   [:identity-file {:optional true} [:maybe [:string {:min 1}]]]
   [:ready-timeout-ms {:optional true} [:int {:min 1}]]])

;; =============================================================================
;; Pure: spec -> request, catalog -> price, pod body -> ssh target
;; =============================================================================

(defn pod-request
  "The v2 create body for `spec`. Pure. Ssh (22/tcp) is always exposed."
  [{:keys [name gpu-type gpu-count image cloud data-centers disk-gb volume-gb volume-path
           ports env min-cuda]}]
  (cond-> {:name  name
           :image (or image default-image)
           :cloud (str/upper-case (clojure.core/name (or cloud :secure)))
           :gpu   (cond-> {:id gpu-type :count (or gpu-count 1)}
                    min-cuda (assoc :minCudaVersion min-cuda))
           :ports (vec (distinct (into ["22/tcp"] ports)))}
    (seq data-centers) (assoc :dataCenterIds data-centers)
    disk-gb            (assoc :disk disk-gb)
    volume-gb          (assoc :mounts {:persistent {:size volume-gb :path (or volume-path "/workspace")}})
    (seq env)          (assoc :env env)))

(m/=> pod-request [:=> [:cat RunPodSpec] :map])

(defn hourly-price
  "USD/hr renting `spec` per catalog `gpus` (v2 rows), or nil when unpriced."
  [spec gpus]
  (when-let [row (first (filter #(= (:gpu-type spec) (:id %)) gpus))]
    (when-let [p (get-in row [:price (or (:cloud spec) :secure)])]
      (* p (or (:gpu-count spec) 1)))))

(defn spend-check
  "Result<price>: ok when `price` is known and within the spec's cap."
  [spec price stage]
  (cond
    (nil? price)
    (r/err :remote/unpriced {:gpu-type (:gpu-type spec) :stage stage})

    (> price (:max-usd-per-hr spec))
    (r/err :remote/over-spend-cap {:price-usd-per-hr price :max-usd-per-hr (:max-usd-per-hr spec) :stage stage})

    :else (r/ok price)))

(defn ssh-target
  "The HostTarget for a v2 pod body's direct ssh, or nil while not exposed."
  [body spec]
  (let [{:keys [host port username]} (get-in body [:ssh :direct])]
    (when (and host port)
      (cond-> {:host host :port (long port) :user (or username "root")
               :options {"StrictHostKeyChecking" "accept-new"}}
        (:identity-file spec) (assoc :identity-file (:identity-file spec))))))

(defn- rows [body k] (if (sequential? body) body (get body k)))

;; =============================================================================
;; Effects, all through the injected :http and :schedule
;; =============================================================================

(defn- terminate-pod! [http id]
  (let [res (http {:method :post :path (str "/pods/" id "/action") :body {:action "terminate"}})]
    (if (= :remote/not-found (:error res))
      (r/ok {:id id :terminated? true :already-gone? true})
      (r/map-ok res (fn [_] {:id id :terminated? true})))))

(defn- await-ssh!
  "Poll the pod until it exposes ssh, at most `timeout-ms`, `poll-ms` apart."
  [http id spec timeout-ms poll-ms sleep!]
  (loop [waited 0]
    (let [res (http {:method :get :path (str "/pods/" id)})]
      (cond
        (r/err? res) res
        (ssh-target (:ok res) spec) (r/ok (:ok res))
        (>= waited timeout-ms) (r/err :remote/pod-not-ready {:id id :waited-ms waited})
        :else (do (sleep! poll-ms) (recur (+ waited poll-ms)))))))

(defn- fail-and-terminate!
  [http id e]
  (let [t (terminate-pod! http id)]
    (when (r/err? t) (log/error "runpod: terminate after failed provision failed; the pod may bill" {:id id :result t}))
    (assoc e :terminated? (r/ok? t) :id id)))

(defrecord RunPodProvider [http schedule sleep! shell process ttls poll-ms]
  ports/IHostProvider
  (provision! [_ spec]
    (if-not (m/validate RunPodSpec spec)
      (r/err :remote/invalid-spec {:explain (m/explain RunPodSpec spec)
                                   :message "a RunPod spec needs :max-usd-per-hr and :ttl-ms"})
      (r/let-ok [catalog (http {:method :get :path "/catalog/gpus"})
                 _       (spend-check spec (hourly-price spec (rows catalog :gpus)) :catalog)
                 created (http {:method :post :path "/pods" :body (pod-request spec)})]
        (let [id     (:id created)
              cancel (schedule (:ttl-ms spec)
                               #(let [t (terminate-pod! http id)]
                                  (log/warn "runpod: TTL reached, terminated" {:id id :result t})))]
          (swap! ttls assoc id cancel)
          (let [checked (if-let [cost (:cost created)]
                          (spend-check spec cost :created)
                          (r/ok nil))
                ready   (when (r/ok? checked)
                          (await-ssh! http id spec (or (:ready-timeout-ms spec) 600000) poll-ms sleep!))]
            (cond
              (r/err? checked) (do (swap! ttls dissoc id) (cancel) (fail-and-terminate! http id checked))
              (r/err? ready)   (do (swap! ttls dissoc id) (cancel) (fail-and-terminate! http id ready))
              :else (r/ok {:id   id
                           :host (ssh/ssh-host (ssh-target (:ok ready) spec) shell process)})))))))
  (terminate! [_ id]
    (when-let [cancel (get @ttls id)]
      (swap! ttls dissoc id)
      (cancel))
    (terminate-pod! http id)))

;; =============================================================================
;; Live collaborators
;; =============================================================================

(defn- query-string [query]
  (when (seq query)
    (str "?" (str/join "&" (for [[k v] query, x (if (sequential? v) v [v])]
                             (str (URLEncoder/encode (str k) "UTF-8") "=" (URLEncoder/encode (str x) "UTF-8")))))))

(defn http-caller
  "The live :http fn: one authenticated REST call per use. `cfg`:
   :base-url, :api-key-env (default RUNPOD_API_KEY)."
  [{:keys [base-url api-key-env] :or {base-url default-base-url api-key-env "RUNPOD_API_KEY"}}]
  (let [client (-> (HttpClient/newBuilder) (.connectTimeout (Duration/ofSeconds 15)) (.build))]
    (fn [{:keys [method path query body]}]
      (if-let [k (not-empty (System/getenv api-key-env))]
        (let [b    (-> (HttpRequest/newBuilder (URI/create (str base-url path (query-string query))))
                       (.header "Authorization" (str "Bearer " k))
                       (.header "Content-Type" "application/json")
                       (.timeout (Duration/ofSeconds 30)))
              b    (case method
                     :get  (.GET b)
                     :post (.POST b (HttpRequest$BodyPublishers/ofString (json/write-str (or body {}))))
                     :delete (.DELETE b))
              resp (r/try-effect* :remote/provider-unreachable
                     (.send client (.build b) (HttpResponse$BodyHandlers/ofString)))]
          (r/let-ok [resp resp]
            (let [status (.statusCode resp) text (.body resp)]
              (cond
                (<= 200 status 299) (r/try-effect* :remote/provider-unparsable
                                      (when-not (str/blank? text) (json/read-str text :key-fn keyword)))
                (= 404 status)      (r/err :remote/not-found {:path path})
                :else               (r/err :remote/provider-refused {:path path :status status})))))
        (r/err :remote/credentials-missing {:message (str "No RunPod API key: set " api-key-env)})))))

(defn timer-schedule
  "A :schedule fn on one daemon Timer: (fn [ms f]) -> cancel fn."
  []
  (let [timer (Timer. "runpod-ttl" true)]
    (fn [ms f]
      (let [task (proxy [TimerTask] [] (run [] (try (f) (catch Throwable t (log/error t "runpod: TTL task threw")))))]
        (.schedule timer task (long ms))
        (fn [] (.cancel task))))))

(defn runpod-provider
  "An IHostProvider renting RunPod pods. `cfg`: :shell and :process (for the
   ssh host), optional :http, :schedule, :sleep!, :poll-ms, plus
   `http-caller`'s keys."
  [{:keys [shell process http schedule sleep! poll-ms] :as cfg}]
  (->RunPodProvider (or http (http-caller cfg))
                    (or schedule (timer-schedule))
                    (or sleep! #(Thread/sleep (long %)))
                    shell process (atom {}) (or poll-ms 5000)))

(defmethod ports/host-provider :runpod [{:keys [shell process] :as cfg}]
  (if (and shell process)
    (r/ok (runpod-provider cfg))
    (r/err :remote/invalid-config {:kind :runpod :needs [:shell :process]})))
