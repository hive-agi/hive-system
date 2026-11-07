(ns hive-system.remote.k8s
  "IRemoteHost and IHostProvider over a running Kubernetes pod, driven by the
   kubectl client through the local IShell (exec, cp, health, pod lookup) and
   IProcess (held port-forwards) ports.

   The provider ATTACHES to a pod that already runs, by name or by label
   selector (first Running pod); it never creates or deletes workloads, so
   terminate! is a no-op that says so. argv building is pure (PodTarget ->
   argv) and kept apart from the record that runs it."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.remote.ports :as ports]
            [hive-system.remote.target :as target]
            [malli.core :as m]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def PodTarget
  "Where a pod is and how to reach it with kubectl."
  [:map
   [:namespace [:string {:min 1}]]
   [:pod [:string {:min 1}]]
   [:container {:optional true} [:maybe [:string {:min 1}]]]
   [:context {:optional true} [:maybe [:string {:min 1}]]]
   [:kubeconfig {:optional true} [:maybe [:string {:min 1}]]]])

(def K8sSpec
  "provision! spec: a namespace plus EITHER :pod or a label :selector."
  [:and
   [:map
    [:namespace [:string {:min 1}]]
    [:pod {:optional true} [:string {:min 1}]]
    [:selector {:optional true} [:string {:min 1}]]
    [:container {:optional true} [:maybe [:string {:min 1}]]]
    [:context {:optional true} [:maybe [:string {:min 1}]]]
    [:kubeconfig {:optional true} [:maybe [:string {:min 1}]]]]
   [:fn {:error/message "exactly one of :pod or :selector"}
    (fn [{:keys [pod selector]}] (not= (some? pod) (some? selector)))]])

(def ^:private Argv [:vector :string])

(defn- kubectl
  "kubectl plus the global flags `t` asks for."
  [{:keys [context kubeconfig namespace]}]
  (cond-> ["kubectl"]
    kubeconfig (into ["--kubeconfig" kubeconfig])
    context    (into ["--context" context])
    true       (into ["-n" namespace])))

(defn- container-args [{:keys [container]}] (if container ["-c" container] []))

(defn exec-argv
  "argv running `cmd` in the pod: a string through `sh -c`, an argv as given.
   stdin is attached (-i) so :in reaches the remote process."
  [t cmd]
  (-> (kubectl t)
      (into ["exec" "-i" (:pod t)])
      (into (container-args t))
      (into ["--"])
      (into (if (string? cmd) ["sh" "-c" cmd] cmd))))

(m/=> exec-argv [:=> [:cat PodTarget target/Command] Argv])

(defn- pod-path [t path] (str (:namespace t) "/" (:pod t) ":" path))

(defn put-argv
  "argv copying `local-path` into the pod at `remote-path`."
  [t local-path remote-path]
  (-> (kubectl t) (into ["cp"]) (into (container-args t)) (into [local-path (pod-path t remote-path)])))

(m/=> put-argv [:=> [:cat PodTarget [:string {:min 1}] [:string {:min 1}]] Argv])

(defn get-argv
  "argv copying `remote-path` out of the pod to `local-path`."
  [t remote-path local-path]
  (-> (kubectl t) (into ["cp"]) (into (container-args t)) (into [(pod-path t remote-path) local-path])))

(m/=> get-argv [:=> [:cat PodTarget [:string {:min 1}] [:string {:min 1}]] Argv])

(defn forward-argv
  "argv holding 127.0.0.1:local-port -> the pod's remote-port until signalled."
  [t local-port remote-port]
  (into (kubectl t) ["port-forward" "--address" "127.0.0.1"
                     (str "pod/" (:pod t)) (str local-port ":" remote-port)]))

(m/=> forward-argv [:=> [:cat PodTarget target/Port target/Port] Argv])

(defn running-pod-argv
  "argv listing pod names and phases matching `selector`, one per line."
  [t selector]
  (into (kubectl t) ["get" "pods" "-l" selector "-o"
                     "jsonpath={range .items[*]}{.metadata.name} {.status.phase}{\"\\n\"}{end}"]))

(defn first-running
  "The first pod name in `running-pod-argv` output whose phase is Running."
  [stdout]
  (some (fn [line]
          (let [[pod phase] (str/split (str/trim line) #"\s+")]
            (when (= "Running" phase) pod)))
        (str/split-lines (or stdout ""))))

(m/=> first-running [:=> [:cat [:maybe :string]] [:maybe :string]])

;; =============================================================================
;; The host
;; =============================================================================

(def ^:private default-timeout-ms 60000)

(defn- shell-opts
  [opts]
  (cond-> {:timeout-ms (or (:timeout-ms opts) default-timeout-ms)}
    (some? (:in opts)) (assoc :in (:in opts))))

(defn- copy!
  [shell argv opts err-key ok-value]
  (r/let-ok [res (proto/shell-exec! shell argv (shell-opts opts))]
    (if (zero? (:exit res))
      (r/ok ok-value)
      (r/err err-key (merge ok-value (select-keys res [:exit :stderr]))))))

(defrecord K8sHost [target shell process forwards]
  ports/IRemoteHost
  (remote-exec! [_ cmd opts]
    (proto/shell-exec! shell (exec-argv target cmd) (shell-opts opts)))

  (remote-put! [_ local-path remote-path opts]
    (copy! shell (put-argv target local-path remote-path) opts
           :remote/put-failed {:local-path local-path :remote-path remote-path}))

  (remote-get! [_ remote-path local-path opts]
    (copy! shell (get-argv target remote-path local-path) opts
           :remote/get-failed {:remote-path remote-path :local-path local-path}))

  (remote-forward! [_ local-port remote-port opts]
    (let [remote-host (or (:remote-host opts) "127.0.0.1")]
      (if-not (contains? #{"127.0.0.1" "localhost"} remote-host)
        (r/err :remote/forward-unsupported
               {:remote-host remote-host
                :message     "kubectl port-forward reaches only the pod's own ports"})
        (r/let-ok [handle (proto/process-spawn! process (forward-argv target local-port remote-port)
                                                {:redirect-err? true})]
          (let [id (str "forward-" local-port "-pod-" remote-port)]
            (swap! forwards assoc id handle)
            (r/ok {:forward-id id :local-port local-port :remote-port remote-port}))))))

  (remote-health [_]
    (let [res (proto/shell-exec! shell (exec-argv target ["true"]) {:timeout-ms 15000})]
      (cond
        (r/err? res)              (r/ok {:reachable? false :reason (:error res)})
        (zero? (:exit (:ok res))) (r/ok {:reachable? true})
        :else                     (r/ok {:reachable? false :exit (:exit (:ok res)) :stderr (:stderr (:ok res))}))))

  (remote-release! [_]
    (let [[held _] (reset-vals! forwards {})
          signals  (mapv (fn [[id h]] [id (proto/process-signal! process h :term)]) held)
          failed   (into {} (filter (comp r/err? second)) signals)]
      (if (seq failed)
        (r/err :remote/release-failed {:closed (- (count signals) (count failed))
                                       :failed (vec (keys failed))})
        (r/ok {:closed (count signals)})))))

(defn k8s-host
  "An IRemoteHost reaching the pod `target` (a PodTarget) through `shell`
   (IShell) and `process` (IProcess)."
  [target shell process]
  (->K8sHost target shell process (atom {})))

(m/=> k8s-host [:=> [:cat PodTarget :any :any] :any])

;; =============================================================================
;; The provider
;; =============================================================================

(defn- resolve-pod!
  "Result<pod name>: :pod as given, else the first Running pod for :selector."
  [shell spec]
  (if-let [pod (:pod spec)]
    (r/ok pod)
    (r/let-ok [res (proto/shell-exec! shell (running-pod-argv spec (:selector spec)) {:timeout-ms 30000})]
      (cond
        (not (zero? (:exit res)))
        (r/err :remote/pod-lookup-failed {:selector (:selector spec) :exit (:exit res) :stderr (:stderr res)})

        :else
        (if-let [pod (first-running (:stdout res))]
          (r/ok pod)
          (r/err :remote/no-running-pod {:namespace (:namespace spec) :selector (:selector spec)}))))))

(defrecord K8sProvider [shell process]
  ports/IHostProvider
  (provision! [_ spec]
    (if-not (m/validate K8sSpec spec)
      (r/err :remote/invalid-spec {:explain (m/explain K8sSpec spec)})
      (r/let-ok [pod (resolve-pod! shell spec)]
        (let [t (into {:pod pod}
                      (filter (comp some? val))
                      (select-keys spec [:namespace :container :context :kubeconfig]))]
          (r/ok {:id   (str (:namespace t) "/" pod)
                 :host (k8s-host t shell process)})))))
  (terminate! [_ id]
    (r/ok {:id id :terminated? false :reason :remote/not-owned})))

(defn k8s-provider
  "An IHostProvider attaching to running pods with kubectl over `shell` and
   `process`."
  [shell process]
  (->K8sProvider shell process))

(defmethod ports/host-provider :k8s [{:keys [shell process]}]
  (if (and shell process)
    (r/ok (k8s-provider shell process))
    (r/err :remote/invalid-config {:kind :k8s :needs [:shell :process]})))
