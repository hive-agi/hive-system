(ns hive-system.shell.detect
  "Detect available package managers and system capabilities.
   Delegates to babashka.fs for path resolution."
  (:require [babashka.fs :as fs]
            [hive-dsl.result :as r]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

(def ^:private pkg-manager-binaries
  "Package manager binary names — resolved via PATH, not hardcoded paths."
  {:brew      "brew"
   :apt       "apt"
   :dnf       "dnf"
   :pacman    "pacman"
   :nix       "nix"
   :conda     "conda"
   :pip       "pip3"
   :cargo     "cargo"
   :npm       "npm"})

(defn detect-pkg-managers
  "Returns a map of {:manager :path} for each available package manager."
  []
  (into {}
        (keep (fn [[mgr bin]]
                (when-let [found (fs/which bin)]
                  [mgr (str found)])))
        pkg-manager-binaries))

(defn which
  "Resolve a binary name to its full path via babashka.fs/which.
   Returns (ok {:path ... :program ...}) or (err :shell/not-found ...)."
  [program]
  (if-let [found (fs/which (str program))]
    (r/ok {:path (str found)
            :program (str program)})
    (r/err :shell/not-found {:program (str program)})))
