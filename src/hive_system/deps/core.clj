(ns hive-system.deps.core
  "DependencyEnsurer — composes IShell + IDistroDetector + IPackageInstaller
   to deliver the user-level `ensure!` verb.

   The record itself is pure-data + dispatch; every side effect goes
   through one of the three injected ports. Tests exercise the policy
   matrix (`:auto` / `:ask` / `:throw`) by feeding fakes."
  (:require [hive-dsl.result :as r]
            [hive-system.protocols :as sys-proto]
            [hive-system.deps.protocols :as proto]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; Internal helpers — small, total, pure where possible
;; =============================================================================

(defn- present?
  "Probe `cmd` via the injected IShell. Returns boolean.
   We accept any ok? Result from shell-which as evidence of presence."
  [shell cmd]
  (r/ok? (sys-proto/shell-which shell cmd)))

(defn- pkg-name-for
  "Look up the package name for `distro` in spec.pkg.
   Returns the string, or nil if the spec has no entry for this distro."
  [spec distro]
  (get-in spec [:pkg distro]))

(defn- install-and-verify
  "Run `install!` then re-probe via `which`. Returns a per-spec
   bucket-tag map, one of:
     {:bucket :installed :spec spec :pkg pkg :install-result …}
     {:bucket :failed    :spec spec :reason :install-failed
                         :install-error (:error install-result) :detail …}
     {:bucket :failed    :spec spec :reason :install-succeeded-but-still-missing
                         :pkg pkg}"
  [shell installer spec pkg]
  (let [install-result (proto/install! installer pkg)]
    (cond
      (r/err? install-result)
      {:bucket :failed
       :spec spec
       :reason :install-failed
       :install-error (:error install-result)
       :detail (dissoc install-result :error)}

      (present? shell (:cmd spec))
      {:bucket :installed
       :spec spec
       :pkg pkg
       :install-result install-result}

      :else
      {:bucket :failed
       :spec spec
       :reason :install-succeeded-but-still-missing
       :pkg pkg})))

(defn- default-prompt-fn
  "Default prompt that refuses to assume consent. Tests inject their own."
  [_spec]
  (r/err :deps/needs-prompt-fn
         {:message "ensure! got a spec with :on-missing :ask but no :prompt-fn was injected"}))

(defn- handle-missing
  "Apply the :on-missing policy for one spec. Returns a bucket-tag map
   (see install-and-verify for shape)."
  [{:keys [shell distro-detector package-installer prompt-fn]
    :or   {prompt-fn default-prompt-fn}}
   distro spec]
  (let [pkg (pkg-name-for spec distro)]
    (cond
      (nil? pkg)
      {:bucket :failed
       :spec spec
       :reason :pkg-name-missing-for-distro
       :distro distro}

      :else
      (case (:on-missing spec :ask)
        :auto
        (install-and-verify shell package-installer spec pkg)

        :throw
        {:bucket :failed
         :spec spec
         :reason :missing
         :pkg pkg
         :distro distro}

        :ask
        (let [prompt-result (prompt-fn (assoc spec :resolved-pkg pkg :distro distro))]
          (cond
            (r/err? prompt-result)
            {:bucket :failed
             :spec spec
             :reason (:error prompt-result)
             :detail (dissoc prompt-result :error)}

            ;; ok with truthy value → consent given, install
            (and (r/ok? prompt-result) (:ok prompt-result))
            (install-and-verify shell package-installer spec pkg)

            ;; ok with falsy value → user declined
            :else
            {:bucket :failed
             :spec spec
             :reason :user-declined
             :pkg pkg}))

        ;; Unknown policy
        {:bucket :failed
         :spec spec
         :reason :unknown-on-missing-policy
         :on-missing (:on-missing spec)
         :distro distro
         :pkg pkg}))))

(defn- process-spec
  "Run one spec end-to-end. Returns a bucket-tag map."
  [ensurer distro spec]
  (let [{:keys [shell]} ensurer
        cmd (:cmd spec)]
    (if (present? shell cmd)
      {:bucket :already-present :spec spec :cmd cmd}
      (handle-missing ensurer distro spec))))

(defn- accumulate
  "Bucket a tag map into the running summary."
  [summary tag]
  (let [bucket (:bucket tag)
        entry (dissoc tag :bucket)]
    (update summary bucket (fnil conj []) entry)))

(def ^:private empty-summary
  {:installed [] :already-present [] :failed []})

;; =============================================================================
;; DependencyEnsurer record
;; =============================================================================

(defrecord DependencyEnsurer [shell distro-detector package-installer prompt-fn]
  proto/IDependencyEnsurer
  (ensure! [this specs]
    (let [distro-result (proto/detect-distro distro-detector)]
      (if (r/err? distro-result)
        ;; Distro detection failure is fatal — we cannot pick :pkg keys.
        (r/err :deps/distro-detection-failed
               {:cause distro-result
                :specs specs})
        (let [distro (:ok distro-result)
              summary (reduce (fn [acc spec]
                                (accumulate acc (process-spec this distro spec)))
                              empty-summary
                              specs)]
          (r/ok (assoc summary :distro distro)))))))

(defn make-ensurer
  "Construct a DependencyEnsurer.

   Required:
     :shell             — IShell impl (used for `which`)
     :distro-detector   — IDistroDetector impl
     :package-installer — IPackageInstaller impl

   Optional:
     :prompt-fn — (fn [spec]) → Result<bool>. Called for specs with
                  :on-missing :ask. ok-truthy = install, ok-falsy =
                  decline, err = abort that spec into :failed."
  [{:keys [shell distro-detector package-installer prompt-fn]}]
  (->DependencyEnsurer shell distro-detector package-installer
                       (or prompt-fn default-prompt-fn)))
