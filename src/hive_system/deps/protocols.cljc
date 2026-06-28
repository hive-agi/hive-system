(ns hive-system.deps.protocols
  "Protocols for the dependency-ensurer subsystem.

   ## Why this exists

   Tools that shell out (`ssh`, `sshpass`, `pass`, `gpg`, `clojure`, …)
   currently assume the binary is on PATH. When missing, calls explode
   with a confusing `IOException: Cannot run program …` deep in
   babashka.process. This namespace introduces the user-level verb
   \"make sure I can call X\" — composing narrower ports
   (`IShell` from `hive-system.protocols`, plus `IDistroDetector` and
   `IPackageInstaller` defined here) so each impl stays ISP-narrow.

   ## ISP boundary

   - `IDistroDetector`  — \"which Linux/BSD/macOS family am I on?\"
     One axis of variance: distro identity. Pure-ish (reads
     `/etc/os-release`, `uname`, etc.).
   - `IPackageInstaller` — \"install package X via the system pkg mgr\".
     One axis of variance: package manager (apt / dnf / pacman / brew …).
     All side effects.
   - `IDependencyEnsurer` — the user-level facade that composes the
     above three to deliver a single `ensure!` verb.

   New distros plug in via new `IDistroDetector` impls; new package
   managers via new `IPackageInstaller` impls. `IDependencyEnsurer`
   itself stays distro/manager-agnostic."
  )

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; IDistroDetector — \"what OS family am I on?\"
;; =============================================================================

(defprotocol IDistroDetector
  "Detect the operating-system / distro identity of the local host.

   The returned keyword is the lookup key used inside dependency specs:
   `:apt`, `:dnf`, `:pacman`, `:brew`, `:nix`, `:zypper`, …

   We key by *package manager family*, not distro name, because that's
   what call sites actually need (\"which key do I read from
   `:pkg {:apt … :dnf …}`?\"). A distro that ships multiple managers
   should pick the canonical one for its baseline (e.g. Ubuntu → `:apt`,
   Fedora → `:dnf`)."
  (detect-distro [this]
    "Returns Result<keyword> identifying the package-manager family.
     Errors namespaced under `:distro/` (e.g. `:distro/unknown`,
     `:distro/unsupported`)."))

;; =============================================================================
;; IPackageInstaller — \"install package X\"
;; =============================================================================

(defprotocol IPackageInstaller
  "Install OS packages via the host's native package manager.

   Implementations are expected to be one-package-manager-each
   (AptInstaller, DnfInstaller, PacmanInstaller, BrewInstaller, …).
   The `family` key MUST match the keyword returned by an
   `IDistroDetector` impl that selects this installer."
  (installer-family [this]
    "Keyword identifying the package-manager family (`:apt`, `:dnf`, …).
     MUST be stable.")
  (install! [this pkg-name]
    "Install a single package by name. Returns Result.

     - ok  → {:pkg pkg-name :installer family :stdout … :stderr …}
     - err → namespaced under installer family
             (e.g. `:apt/install-failed`, `:dnf/install-failed`)."))

;; =============================================================================
;; IDependencyEnsurer — user-level facade
;; =============================================================================

(defprotocol IDependencyEnsurer
  "Ensure a set of CLI tools are available on the host, installing
   the backing OS packages on demand when permitted.

   `ensure!` accepts a vector of specs, each describing one binary:

       {:cmd        \"ssh\"
        :pkg        {:apt    \"openssh-client\"
                     :dnf    \"openssh-clients\"
                     :pacman \"openssh\"}
        :on-missing :auto | :ask | :throw}

   - `:cmd` is the binary to look up via `which`.
   - `:pkg` maps each package-manager family to the package name on
     that family. The callee owns this mapping because the package
     name varies per OS (e.g. `openssh-client` vs `openssh-clients`).
   - `:on-missing` selects the policy when the binary is absent:
     - `:auto`  → install via `IPackageInstaller`, then re-verify.
     - `:ask`   → call the injected `prompt-fn`; install only on
                  user consent.
     - `:throw` → return `:deps/missing` immediately, no install.

   Returns Result<{:installed [...] :already-present [...] :failed [...]}>.
   The summary is always wrapped in `ok` — individual failures are
   reported in the `:failed` bucket. The wrapper is `err` only when
   the overall computation could not run (e.g. distro detection
   itself failed in a way that prevents progress)."
  (ensure! [this specs]
    "Process every spec in `specs` and return a summary.
     See protocol docstring for the contract."))
