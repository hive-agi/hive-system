(ns hive-system.deps.core-test
  "Behavioural tests for DependencyEnsurer.

   The injected ports are faked end-to-end:
     - FakeShell tracks calls + answers shell-which from a presence map.
     - FakeDistroDetector returns a fixed family.
     - FakeInstaller records every install! call, optionally toggling
       presence in the shell on success.

   These fakes give us a hermetic environment where we can exercise:
     - already-present (no install fired)
     - missing :auto (install fired, presence flips, bucket :installed)
     - missing :auto with install failure (bucket :failed, reason :install-failed)
     - missing :auto where install \"succeeds\" but binary still absent
       (bucket :failed, reason :install-succeeded-but-still-missing)
     - missing :ask consent → install
     - missing :ask decline → bucket :failed, reason :user-declined
     - missing :ask with no prompt-fn → bucket :failed, reason :deps/needs-prompt-fn
     - missing :throw → bucket :failed, reason :missing
     - spec without a key for the detected distro → :failed :reason :pkg-name-missing-for-distro
     - distro detection failure → top-level err :deps/distro-detection-failed
     - mixed batch (some present, some installed, some failed)"
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as sys-proto]
            [hive-system.deps.protocols :as proto]
            [hive-system.deps.core :as deps]))

;; =============================================================================
;; Fakes
;; =============================================================================

(defrecord FakeShell [presence calls]
  sys-proto/IShell
  (shell-exec! [_ cmd opts]
    (swap! calls conj [:exec cmd opts])
    (r/ok {:exit 0 :stdout "" :stderr "" :duration-ms 0 :cmd cmd}))
  (shell-env [_] {})
  (shell-which [_ program]
    (swap! calls conj [:which program])
    (if (contains? @presence program)
      (r/ok {:path (str "/usr/bin/" program) :program program})
      (r/err :shell/not-found {:program program}))))

(defn make-fake-shell
  "Construct a FakeShell pre-seeded with the binaries in `present-set`."
  ([] (make-fake-shell #{}))
  ([present-set]
   (->FakeShell (atom (set present-set)) (atom []))))

(defn shell-calls [fs] @(:calls fs))

(defrecord FakeDistroDetector [result]
  proto/IDistroDetector
  (detect-distro [_] result))

(defn make-fake-detector
  "FakeDistroDetector returning `result` from detect-distro.
   Helper :family kw form is shorthand for (r/ok family)."
  [result]
  (->FakeDistroDetector
   (if (keyword? result) (r/ok result) result)))

(defrecord FakeInstaller [family install-fn calls]
  proto/IPackageInstaller
  (installer-family [_] family)
  (install! [_ pkg]
    (swap! calls conj pkg)
    (install-fn pkg)))

(defn make-fake-installer
  "Construct a FakeInstaller. `install-fn` is (fn [pkg]) → Result.

   When the convenience flag :auto-flip-presence? is given with a
   FakeShell ref, a successful install! also adds :cmd to that
   shell's presence set so the ensurer's re-probe sees the binary."
  ([family] (make-fake-installer family (fn [pkg] (r/ok {:pkg pkg :installer family}))))
  ([family install-fn]
   (->FakeInstaller family install-fn (atom []))))

(defn make-flipping-installer
  "Installer that, on a successful (r/ok …) install!, also flips
   `cmd` to present in the given fake shell. `pkg->cmd` resolves the
   binary that should appear once `pkg` is installed."
  [family shell pkg->cmd]
  (let [base (fn [pkg]
               (when-let [cmd (pkg->cmd pkg)]
                 (swap! (:presence shell) conj cmd))
               (r/ok {:pkg pkg :installer family :stdout "" :stderr ""}))]
    (make-fake-installer family base)))

(defn installer-calls [fi] @(:calls fi))

;; =============================================================================
;; Helpers
;; =============================================================================

(defn make-ensurer
  "Build a DependencyEnsurer with the given fakes."
  [{:keys [shell detector installer prompt-fn]}]
  (deps/make-ensurer
   {:shell shell
    :distro-detector detector
    :package-installer installer
    :prompt-fn prompt-fn}))

(def ssh-spec-debian
  {:cmd "ssh"
   :pkg {:apt "openssh-client"
         :dnf "openssh-clients"
         :pacman "openssh"}
   :on-missing :auto})

;; =============================================================================
;; already-present
;; =============================================================================

(deftest ensure!-already-present-no-install
  (testing "binary already on PATH → bucketed :already-present, no install fired"
    (let [shell (make-fake-shell #{"ssh"})
          detector (make-fake-detector :apt)
          installer (make-fake-installer :apt)
          e (make-ensurer {:shell shell :detector detector :installer installer})
          result (proto/ensure! e [ssh-spec-debian])]
      (is (r/ok? result))
      (is (= :apt (get-in result [:ok :distro])))
      (is (= 1 (count (get-in result [:ok :already-present]))))
      (is (= "ssh" (get-in result [:ok :already-present 0 :cmd])))
      (is (empty? (get-in result [:ok :installed])))
      (is (empty? (get-in result [:ok :failed])))
      (is (empty? (installer-calls installer))
          "install! must NOT be called for already-present binaries"))))

;; =============================================================================
;; :auto policy
;; =============================================================================

(deftest ensure!-auto-installs-and-verifies
  (testing ":auto missing → install fires, presence flips, bucket :installed"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-flipping-installer :apt shell {"openssh-client" "ssh"})
          e (make-ensurer {:shell shell :detector detector :installer installer})
          result (proto/ensure! e [ssh-spec-debian])]
      (is (r/ok? result))
      (is (= ["openssh-client"] (installer-calls installer)))
      (let [installed (get-in result [:ok :installed])]
        (is (= 1 (count installed)))
        (is (= "ssh" (get-in installed [0 :spec :cmd])))
        (is (= "openssh-client" (get-in installed [0 :pkg]))))
      (is (empty? (get-in result [:ok :failed]))))))

(deftest ensure!-auto-install-fails
  (testing ":auto missing + install errors → bucket :failed reason :install-failed"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-fake-installer
                     :apt
                     (fn [pkg] (r/err :apt/install-failed
                                      {:pkg pkg :exit 100 :stderr "E: locked"})))
          e (make-ensurer {:shell shell :detector detector :installer installer})
          result (proto/ensure! e [ssh-spec-debian])]
      (is (r/ok? result))
      (is (= ["openssh-client"] (installer-calls installer)))
      (let [failed (get-in result [:ok :failed])]
        (is (= 1 (count failed)))
        (is (= :install-failed (get-in failed [0 :reason])))
        (is (= :apt/install-failed (get-in failed [0 :install-error]))))
      (is (empty? (get-in result [:ok :installed]))))))

(deftest ensure!-auto-install-but-still-missing
  (testing ":auto install returns ok but binary still absent → :install-succeeded-but-still-missing"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          ;; This installer reports success but never flips presence,
          ;; modelling a broken/no-op pkg manager.
          installer (make-fake-installer
                     :apt
                     (fn [pkg] (r/ok {:pkg pkg :installer :apt})))
          e (make-ensurer {:shell shell :detector detector :installer installer})
          result (proto/ensure! e [ssh-spec-debian])]
      (is (r/ok? result))
      (let [failed (get-in result [:ok :failed])]
        (is (= 1 (count failed)))
        (is (= :install-succeeded-but-still-missing (get-in failed [0 :reason])))
        (is (= "openssh-client" (get-in failed [0 :pkg])))))))

;; =============================================================================
;; :ask policy
;; =============================================================================

(deftest ensure!-ask-consent-then-install
  (testing ":ask + prompt-fn returns ok-true → install proceeds"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-flipping-installer :apt shell {"openssh-client" "ssh"})
          prompt-calls (atom [])
          prompt-fn (fn [spec]
                      (swap! prompt-calls conj spec)
                      (r/ok true))
          e (make-ensurer {:shell shell :detector detector
                           :installer installer :prompt-fn prompt-fn})
          spec (assoc ssh-spec-debian :on-missing :ask)
          result (proto/ensure! e [spec])]
      (is (r/ok? result))
      (is (= 1 (count @prompt-calls)))
      (is (= :apt (:distro (first @prompt-calls)))
          "prompt-fn receives spec annotated with :distro and :resolved-pkg")
      (is (= "openssh-client" (:resolved-pkg (first @prompt-calls))))
      (is (= ["openssh-client"] (installer-calls installer)))
      (is (= 1 (count (get-in result [:ok :installed])))))))

(deftest ensure!-ask-decline-no-install
  (testing ":ask + prompt-fn returns ok-false → no install, bucket :failed :user-declined"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-fake-installer :apt)
          prompt-fn (fn [_] (r/ok false))
          e (make-ensurer {:shell shell :detector detector
                           :installer installer :prompt-fn prompt-fn})
          spec (assoc ssh-spec-debian :on-missing :ask)
          result (proto/ensure! e [spec])]
      (is (r/ok? result))
      (is (empty? (installer-calls installer))
          "install! must NOT be called when user declines")
      (let [failed (get-in result [:ok :failed])]
        (is (= 1 (count failed)))
        (is (= :user-declined (get-in failed [0 :reason])))
        (is (= "openssh-client" (get-in failed [0 :pkg])))))))

(deftest ensure!-ask-without-prompt-fn-fails
  (testing ":ask with no prompt-fn injected → bucket :failed :deps/needs-prompt-fn"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-fake-installer :apt)
          e (make-ensurer {:shell shell :detector detector :installer installer})
          spec (assoc ssh-spec-debian :on-missing :ask)
          result (proto/ensure! e [spec])]
      (is (r/ok? result))
      (is (empty? (installer-calls installer)))
      (let [failed (get-in result [:ok :failed])]
        (is (= 1 (count failed)))
        (is (= :deps/needs-prompt-fn (get-in failed [0 :reason])))))))

;; =============================================================================
;; :throw policy
;; =============================================================================

(deftest ensure!-throw-policy
  (testing ":throw on missing → bucket :failed :missing, no install fired"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-fake-installer :apt)
          e (make-ensurer {:shell shell :detector detector :installer installer})
          spec (assoc ssh-spec-debian :on-missing :throw)
          result (proto/ensure! e [spec])]
      (is (r/ok? result))
      (is (empty? (installer-calls installer)))
      (let [failed (get-in result [:ok :failed])]
        (is (= 1 (count failed)))
        (is (= :missing (get-in failed [0 :reason])))
        (is (= "openssh-client" (get-in failed [0 :pkg])))
        (is (= :apt (get-in failed [0 :distro])))))))

;; =============================================================================
;; spec without a :pkg entry for detected distro
;; =============================================================================

(deftest ensure!-no-pkg-for-distro
  (testing "spec :pkg map missing detected-distro key → :failed :pkg-name-missing-for-distro"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :pacman)
          installer (make-fake-installer :pacman)
          e (make-ensurer {:shell shell :detector detector :installer installer})
          ;; spec only knows :apt and :dnf — no :pacman entry
          spec {:cmd "exotic"
                :pkg {:apt "exotic-deb" :dnf "exotic-rpm"}
                :on-missing :auto}
          result (proto/ensure! e [spec])]
      (is (r/ok? result))
      (is (empty? (installer-calls installer))
          "install! must NOT fire when we don't even know the package name")
      (let [failed (get-in result [:ok :failed])]
        (is (= 1 (count failed)))
        (is (= :pkg-name-missing-for-distro (get-in failed [0 :reason])))
        (is (= :pacman (get-in failed [0 :distro])))))))

;; =============================================================================
;; distro detection failure is fatal
;; =============================================================================

(deftest ensure!-distro-detection-failed
  (testing "detector returns err → ensure! returns top-level err :deps/distro-detection-failed"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector (r/err :distro/unknown {:source "test"}))
          installer (make-fake-installer :apt)
          e (make-ensurer {:shell shell :detector detector :installer installer})
          result (proto/ensure! e [ssh-spec-debian])]
      (is (r/err? result))
      (is (= :deps/distro-detection-failed (:error result)))
      (is (empty? (installer-calls installer))))))

;; =============================================================================
;; Mixed batch
;; =============================================================================

(deftest ensure!-mixed-batch
  (testing "batch of three specs: present + auto-installable + throw-missing"
    (let [shell (make-fake-shell #{"git"})
          detector (make-fake-detector :apt)
          installer (make-flipping-installer :apt shell {"openssh-client" "ssh"})
          e (make-ensurer {:shell shell :detector detector :installer installer})
          specs [ssh-spec-debian
                 {:cmd "git" :pkg {:apt "git"} :on-missing :auto}
                 {:cmd "exotic" :pkg {:apt "exotic-deb"} :on-missing :throw}]
          result (proto/ensure! e specs)]
      (is (r/ok? result))
      (let [{:keys [installed already-present failed]} (:ok result)]
        (is (= 1 (count installed)))
        (is (= "ssh" (get-in installed [0 :spec :cmd])))
        (is (= 1 (count already-present)))
        (is (= "git" (get-in already-present [0 :cmd])))
        (is (= 1 (count failed)))
        (is (= :missing (get-in failed [0 :reason])))
        (is (= "exotic" (get-in failed [0 :spec :cmd])))))))

;; =============================================================================
;; Empty input
;; =============================================================================

(deftest ensure!-empty-specs
  (testing "ensure! with [] → ok with empty buckets"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-fake-installer :apt)
          e (make-ensurer {:shell shell :detector detector :installer installer})
          result (proto/ensure! e [])]
      (is (r/ok? result))
      (is (empty? (get-in result [:ok :installed])))
      (is (empty? (get-in result [:ok :already-present])))
      (is (empty? (get-in result [:ok :failed])))
      (is (= :apt (get-in result [:ok :distro]))))))

;; =============================================================================
;; Default :on-missing is :ask (per spec safety stance)
;; =============================================================================

(deftest ensure!-default-policy-is-ask
  (testing "spec without :on-missing key behaves as :ask"
    (let [shell (make-fake-shell #{})
          detector (make-fake-detector :apt)
          installer (make-fake-installer :apt)
          prompt-calls (atom 0)
          prompt-fn (fn [_] (swap! prompt-calls inc) (r/ok false))
          e (make-ensurer {:shell shell :detector detector
                           :installer installer :prompt-fn prompt-fn})
          spec {:cmd "ssh" :pkg {:apt "openssh-client"}}
          result (proto/ensure! e [spec])]
      (is (r/ok? result))
      (is (= 1 @prompt-calls) "prompt-fn must be called for default policy")
      (is (= :user-declined (get-in result [:ok :failed 0 :reason]))))))
