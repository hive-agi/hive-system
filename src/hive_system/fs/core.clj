(ns hive-system.fs.core
  "IPathQuery implementation backed by babashka.fs.
   All operations return hive-dsl Results for railway composition.

   Convenience API (stateless, default instance):
     (exists? path)           → Result<boolean>
     (directory? path)        → Result<boolean>
     (absolute-dir? path)     → Result<boolean>
     (resolve-first-dir [...]) → Result<string>
     (find-files path exts)   → Result<vec<string>>
     (expand-path path exts)  → vec<string> (rescue-wrapped)

   DIP: consumers depend on IPathQuery protocol, not this impl.
   Swap FsPathQuery for a test double via make-path-query or protocol."
  (:require [hive-system.protocols :as proto]
            [hive-dsl.result :as r :refer [try-effect*]]
            [hive-weave.parallel :as wp]
            [babashka.fs :as fs]
            [clojure.string :as str]
            [taoensso.timbre :as log]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; =============================================================================
;; IPathQuery Implementation
;; =============================================================================

(defrecord FsPathQuery []
  proto/IPathQuery
  (path-exists? [_ path]
    (try-effect* :fs/check-failed
      (boolean (fs/exists? path))))

  (path-directory? [_ path]
    (try-effect* :fs/check-failed
      (boolean (fs/directory? path))))

  (path-file? [_ path]
    (try-effect* :fs/check-failed
      (boolean (fs/regular-file? path))))

  (path-absolute? [_ path]
    (try-effect* :fs/check-failed
      (boolean (fs/absolute? path))))

  (path-resolve [_ base segments]
    (try-effect* :fs/resolve-failed
      (str (reduce fs/path (fs/path base) segments))))

  (path-children [_ dir opts]
    (try-effect* :fs/list-failed
      (let [filter-fn (case (:filter opts :all)
                        :dirs  fs/directory?
                        :files fs/regular-file?
                        :all   (constantly true))
            skip      (or (:skip opts) #{})
            entries   (fs/list-dir dir)]
        (->> entries
             (filter (fn [p]
                       (let [name (str (fs/file-name p))]
                         (and (not (contains? skip name))
                              (filter-fn p)))))
             (mapv str))))))

;; =============================================================================
;; Convenience API (stateless default instance)
;; =============================================================================

(def ^:private default-pq (delay (->FsPathQuery)))

(defn make-path-query
  "Create a FsPathQuery instance. For DI injection or test doubles."
  [] (->FsPathQuery))

(defn exists?
  "Check path existence. Returns Result<boolean>."
  [path]
  (proto/path-exists? @default-pq path))

(defn directory?
  "Check if path is directory. Returns Result<boolean>."
  [path]
  (proto/path-directory? @default-pq path))

(defn file?
  "Check if path is regular file. Returns Result<boolean>."
  [path]
  (proto/path-file? @default-pq path))

(defn absolute?
  "Check if path is absolute. Returns Result<boolean> (pure, no IO)."
  [path]
  (proto/path-absolute? @default-pq path))

(defn resolve-path
  "Join + normalize path segments. Returns Result<string>."
  [base & segments]
  (proto/path-resolve @default-pq base segments))

(defn children
  "List immediate children. Returns Result<vec<string>>.
   opts: {:filter :dirs|:files|:all, :skip #{\"node_modules\" ...}}"
  ([dir] (children dir {}))
  ([dir opts] (proto/path-children @default-pq dir opts)))

;; =============================================================================
;; Composite Predicates
;; =============================================================================

(defn absolute-dir?
  "Check if path is both absolute and an existing directory.
   Returns Result<boolean>. Railway-safe."
  [path]
  (r/let-ok [abs (absolute? path)
             dir (directory? path)]
    (r/ok (and abs dir))))

;; =============================================================================
;; Recursive File Discovery
;; =============================================================================

(defn find-files
  "Recursively find files matching extensions under path.
   If path is a file matching exts, returns [path].
   If path is a directory, walks recursively.
   Returns Result<vec<string>>.

   (find-files \"/src\" #{\"clj\" \"cljs\" \"cljc\"})
   => (ok [\"/src/a.clj\" \"/src/b/c.cljs\"])"
  [path exts]
  (try-effect* :fs/find-failed
    (let [ext-set (set exts)
          match?  (fn [p] (some #(str/ends-with? (str p) (str "." %)) ext-set))]
      (cond
        (not (fs/exists? path))
        []

        (fs/regular-file? path)
        (if (match? path) [(str path)] [])

        (fs/directory? path)
        ;; Use "**." instead of "**/*." so glob also matches files at the
        ;; root of `path`, not just in subdirectories.
        (->> (fs/glob path (str "**.{" (str/join "," ext-set) "}"))
             (mapv str))

        :else []))))

(defn expand-path
  "Expand a path to matching files. Directory → recursive glob.
   File matching exts → [file]. Nonexistent → []. Error → [].
   Returns plain vec (not Result) — rescue-wrapped for pipeline use.

   (expand-path \"/src\" #{\"clj\" \"cljs\"})
   => [\"/src/foo.clj\" \"/src/bar/baz.cljs\"]"
  [path exts]
  (or (:ok (find-files path exts)) []))

;; =============================================================================
;; Railway Combinators
;; =============================================================================

(defn resolve-first-dir
  "Try candidate paths in order, return first existing directory.
   Skips nil candidates. Returns Result<string> or err :fs/no-matching-dir.

   (resolve-first-dir
     [nil
      (hcr-lookup project-id)
      (str hive-root \"/\" project-id)])"
  [candidates]
  (or (some (fn [p]
              (when (and p (string? p))
                (let [r (directory? p)]
                  (when (and (r/ok? r) (:ok r))
                    (r/ok p)))))
            candidates)
      (r/err :fs/no-matching-dir
             {:tried (filterv some? candidates)})))

;; =============================================================================
;; Cargo-Scan: Parallel Directory Scanner
;; =============================================================================

(def ^:private default-skip-dirs
  "Directory names to skip — heavy or irrelevant for project discovery."
  #{"node_modules" "target" ".cpcache" ".git" ".shadow-cljs" ".clj-kondo"
    ".lsp" ".nrepl" "dist" "build" "out" "__pycache__" ".venv" "venv"
    ".gradle" ".m2" "classes" ".gitlibs"})

(defn- scannable?
  "Check if directory should be scanned (not hidden, not in skip set)."
  [path skip-dirs]
  (let [name (str (fs/file-name path))]
    (and (fs/directory? path)
         (not (.startsWith ^String name "."))
         (not (contains? skip-dirs name)))))

(defn- scan-subtree
  "Recursively scan a subtree for marker files. Single-threaded per subtree.
   Returns vec of {:path str :marker-data any}."
  [dir-path {:keys [marker read-marker skip-dirs max-depth]} current-depth]
  (when (and (<= current-depth max-depth)
             (scannable? dir-path skip-dirs))
    (let [marker-file (str (fs/path dir-path marker))
          result      (when (fs/exists? marker-file)
                        {:path       (str dir-path)
                         :marker-data (when read-marker
                                        (read-marker (str dir-path)))})
          child-dirs  (->> (fs/list-dir dir-path)
                           (filter #(scannable? % skip-dirs))
                           (mapcat #(scan-subtree (str %)
                                                  {:marker marker
                                                   :read-marker read-marker
                                                   :skip-dirs skip-dirs
                                                   :max-depth max-depth}
                                                  (inc current-depth))))]
      (if result (cons result child-dirs) child-dirs))))

(defn cargo-scan
  "Parallel directory scanner using hive-weave/bounded-pmap.
   Walks root, finds directories containing :marker file.
   Fan-out at top level, single-threaded per subtree.

   opts:
     :marker       — filename to look for (e.g. \".hive-project.edn\")
     :read-marker  — fn (dir-path) -> data, called when marker found
     :max-depth    — max recursion depth (default 5)
     :concurrency  — parallel workers (default 8)
     :timeout-ms   — per-subtree timeout (default 10000)
     :skip-dirs    — set of dir names to skip (default: default-skip-dirs)

   Returns Result<vec<{:path str :marker-data any}>>."
  [root-path {:keys [marker read-marker max-depth concurrency timeout-ms skip-dirs]
              :or   {max-depth   5
                     concurrency 8
                     timeout-ms  10000
                     skip-dirs   default-skip-dirs}}]
  (try-effect* :fs/cargo-scan-failed
    (when-not marker
      (throw (ex-info "cargo-scan requires :marker" {})))
    (let [root    (str (fs/absolutize root-path))
          opts    {:marker marker :read-marker read-marker
                   :skip-dirs skip-dirs :max-depth max-depth}
          ;; Check root itself
          root-result (let [mf (str (fs/path root marker))]
                        (when (fs/exists? mf)
                          {:path root
                           :marker-data (when read-marker (read-marker root))}))
          ;; Fan-out child directories
          child-dirs  (->> (fs/list-dir root)
                           (filter #(scannable? % skip-dirs))
                           (mapv str))
          child-results (wp/bounded-pmap
                          {:concurrency concurrency
                           :timeout-ms  timeout-ms
                           :fallback    []}
                          (fn [child]
                            (vec (scan-subtree child opts 1)))
                          child-dirs)]
      (cond-> (vec (mapcat identity child-results))
        root-result (conj root-result)))))
