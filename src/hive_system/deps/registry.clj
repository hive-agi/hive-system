(ns hive-system.deps.registry
  "Standard local-host adapters for IDistroDetector and IPackageInstaller,
   plus a `default-ensurer` factory that wires the whole thing up using
   the existing `hive-system.shell.core/make-shell` adapter.

   Adapters here read `/etc/os-release` and shell out to apt-get / dnf /
   pacman / brew via the injected IShell. They never auto-install during
   construction; only `install!` runs effects, and only when explicitly
   invoked by `IDependencyEnsurer/ensure!` under an `:auto` or accepted
   `:ask` policy.

   Tests use *fake* IShell + fake distro/installer impls — see
   `test/hive_system/deps/core_test.clj`."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as sys-proto]
            [hive-system.shell.core :as shell-core]
            [hive-system.deps.protocols :as proto]
            [hive-system.deps.core :as deps-core]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; OsReleaseDistroDetector — reads /etc/os-release via the injected shell
;; =============================================================================

(def ^:private id-like->family
  "Map `ID` / `ID_LIKE` tokens from /etc/os-release to package-manager
   family keywords."
  {"debian"   :apt
   "ubuntu"   :apt
   "linuxmint":apt
   "pop"      :apt
   "fedora"   :dnf
   "rhel"     :dnf
   "centos"   :dnf
   "rocky"    :dnf
   "almalinux":dnf
   "arch"     :pacman
   "manjaro"  :pacman
   "endeavouros" :pacman
   "opensuse" :zypper
   "suse"     :zypper})

(defn- parse-os-release
  "Parse /etc/os-release content into a {ID, ID_LIKE} map."
  [content]
  (->> (str/split-lines (or content ""))
       (keep (fn [line]
               (when-let [[_ k v] (re-matches #"\s*([A-Z_]+)=\"?([^\"]*)\"?\s*" line)]
                 [(str/lower-case k) v])))
       (into {})))

(defn- pick-family
  "From parsed os-release, pick a package-manager family keyword.
   Tries ID first, then each token in ID_LIKE."
  [parsed]
  (let [id (get parsed "id")
        id-like (some-> (get parsed "id_like") (str/split #"\s+"))
        candidates (cons id id-like)]
    (some id-like->family candidates)))

(defrecord OsReleaseDistroDetector [shell]
  proto/IDistroDetector
  (detect-distro [_]
    (let [exec (sys-proto/shell-exec! shell ["cat" "/etc/os-release"] {})]
      (cond
        (r/err? exec)
        (r/err :distro/detect-failed {:cause exec})

        (not (zero? (get-in exec [:ok :exit])))
        (r/err :distro/detect-failed
               {:exit (get-in exec [:ok :exit])
                :stderr (get-in exec [:ok :stderr])})

        :else
        (let [parsed (parse-os-release (get-in exec [:ok :stdout]))
              family (pick-family parsed)]
          (if family
            (r/ok family)
            (r/err :distro/unsupported {:os-release parsed})))))))

(defn make-os-release-detector
  "Construct a /etc/os-release-based IDistroDetector.
   `shell` is an IShell impl."
  [shell]
  (->OsReleaseDistroDetector shell))

;; =============================================================================
;; ShellPackageInstaller — one record, parameterised by family + cmd-builder
;; =============================================================================

(def ^:private family->install-cmd
  "Command-vector builders per family. Each fn takes pkg-name → string-vec."
  {:apt    (fn [pkg] ["sudo" "apt-get" "install" "-y" pkg])
   :dnf    (fn [pkg] ["sudo" "dnf"     "install" "-y" pkg])
   :pacman (fn [pkg] ["sudo" "pacman"  "-S" "--noconfirm" pkg])
   :zypper (fn [pkg] ["sudo" "zypper"  "install" "-y" pkg])
   :brew   (fn [pkg] ["brew" "install" pkg])
   :nix    (fn [pkg] ["nix-env" "-iA" (str "nixpkgs." pkg)])})

(defrecord ShellPackageInstaller [family shell]
  proto/IPackageInstaller
  (installer-family [_] family)
  (install! [_ pkg-name]
    (let [build (get family->install-cmd family)]
      (if-not build
        (r/err (keyword (name family) "unsupported-family")
               {:family family :pkg pkg-name})
        (let [cmd (build pkg-name)
              exec (sys-proto/shell-exec! shell cmd {})]
          (cond
            (r/err? exec)
            (r/err (keyword (name family) "install-failed")
                   {:cmd cmd :pkg pkg-name :cause exec})

            (not (zero? (get-in exec [:ok :exit])))
            (r/err (keyword (name family) "install-failed")
                   {:cmd cmd
                    :pkg pkg-name
                    :exit (get-in exec [:ok :exit])
                    :stdout (get-in exec [:ok :stdout])
                    :stderr (get-in exec [:ok :stderr])})

            :else
            (r/ok {:pkg pkg-name
                   :installer family
                   :stdout (get-in exec [:ok :stdout])
                   :stderr (get-in exec [:ok :stderr])})))))))

(defn make-shell-installer
  "Construct an IPackageInstaller for `family` (`:apt` / `:dnf` /
   `:pacman` / `:zypper` / `:brew` / `:nix`) backed by `shell`."
  [family shell]
  (->ShellPackageInstaller family shell))

;; =============================================================================
;; default-ensurer — wires the standard local-host adapters
;; =============================================================================

(defn default-ensurer
  "Build a DependencyEnsurer using the standard local-host adapters:
     - shell             : hive-system.shell.core/make-shell
     - distro-detector   : OsReleaseDistroDetector
     - package-installer : ShellPackageInstaller (family auto-picked)

   The installer family is fixed at construction time by detecting the
   distro once. If detection fails (unsupported OS, no /etc/os-release)
   we fall back to a stub installer that returns
   `:deps/no-installer-available` for every install attempt — `ensure!`
   then surfaces this in the `:failed` bucket without crashing.

   Opts:
     :prompt-fn — (fn [spec]) → Result<bool> for `:ask` policy
     :shell     — override the IShell impl (defaults to make-shell)"
  ([] (default-ensurer {}))
  ([{:keys [prompt-fn shell] :as _opts}]
   (let [shell (or shell (shell-core/make-shell))
         detector (make-os-release-detector shell)
         distro-result (proto/detect-distro detector)
         installer (if (r/ok? distro-result)
                     (make-shell-installer (:ok distro-result) shell)
                     (reify proto/IPackageInstaller
                       (installer-family [_] :unknown)
                       (install! [_ pkg]
                         (r/err :deps/no-installer-available
                                {:pkg pkg :cause distro-result}))))]
     (deps-core/make-ensurer
      {:shell shell
       :distro-detector detector
       :package-installer installer
       :prompt-fn prompt-fn}))))
