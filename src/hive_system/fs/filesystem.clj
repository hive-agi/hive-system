(ns hive-system.fs.filesystem
  "IFilesystem implementation backed by babashka.fs + java.nio.
   All operations return hive-dsl Results for railway composition.

   Convenience API (stateless, default instance):
     (mkdirs! path)                 → Result<{:path}>
     (tmpdir! prefix)               → Result<{:path}>
     (atomic-write! path content)   → Result<{:path :bytes}>
     (lock! path timeout-ms)        → Result<{:lock}>
     (watch! path patterns handler) → Result<{:watcher}>

   DIP: consumers depend on the IFilesystem protocol, not this impl.
   Swap FsFilesystem for a test double via make-filesystem or the protocol."
  (:require [hive-system.protocols :as proto]
            [hive-dsl.result :as r :refer [try-effect*]]
            [babashka.fs :as fs])
  (:import [java.io RandomAccessFile]
           [java.nio.channels FileChannel FileLock OverlappingFileLockException]
           [java.nio.file ClosedWatchServiceException FileSystems Path PathMatcher
            StandardWatchEventKinds WatchKey WatchService]
           [java.util.concurrent TimeUnit]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

;; =============================================================================
;; Helpers
;; =============================================================================

(defn- glob-matcher
  "A predicate over a child filename for `patterns` (globs). No patterns matches
   everything."
  [patterns]
  (if (empty? patterns)
    (constantly true)
    (let [fsys     (FileSystems/getDefault)
          matchers (mapv #(.getPathMatcher fsys (str "glob:" %)) patterns)]
      (fn [filename]
        (let [p (fs/path (str filename))]
          (boolean (some (fn [^PathMatcher m] (.matches m p)) matchers)))))))

(defn- acquire-lock
  "Poll for an exclusive lock on `path` until `timeout-ms` elapses. Closes the
   backing file on timeout so a failed attempt leaks no descriptor.
   => {:lock FileLock :raf RandomAccessFile} | nil"
  [path timeout-ms]
  (let [raf      (RandomAccessFile. (fs/file path) "rw")
        channel  (.getChannel raf)
        deadline (+ (System/currentTimeMillis) (max 0 (long timeout-ms)))]
    (loop []
      (let [lock (try (.tryLock ^FileChannel channel)
                      (catch OverlappingFileLockException _ nil))]
        (cond
          lock                                    {:lock lock :raf raf}
          (< (System/currentTimeMillis) deadline) (do (Thread/sleep 25) (recur))
          :else                                   (do (.close raf) nil))))))

(defn- write-content!
  "Bytes go through write-bytes; anything else is spat as text."
  [tmp content opts]
  (if (bytes? content)
    (fs/write-bytes tmp content)
    (spit (fs/file tmp) (str content) :encoding (or (:encoding opts) "UTF-8"))))

;; =============================================================================
;; IFilesystem Implementation
;; =============================================================================

(defrecord FsFilesystem []
  proto/IFilesystem

  (fs-mkdirs! [_ path]
    (try-effect* :fs/mkdirs-failed
      (fs/create-dirs path)
      {:path (str path)}))

  (fs-tmpdir! [_ prefix]
    (try-effect* :fs/tmpdir-failed
      {:path (str (fs/create-temp-dir (cond-> {} prefix (assoc :prefix (str prefix)))))}))

  (fs-atomic-write! [_ path content opts]
    (try-effect* :fs/atomic-write-failed
      (let [target (fs/path path)
            parent (or (fs/parent target) (fs/parent (fs/absolutize target)))]
        (fs/create-dirs parent)
        (let [tmp (fs/create-temp-file {:dir parent :prefix ".hs-" :suffix ".tmp"})]
          (try
            (write-content! tmp content opts)
            (fs/move tmp target {:replace-existing true :atomic-move true})
            {:path (str target) :bytes (fs/size target)}
            (catch Throwable t
              (fs/delete-if-exists tmp)
              (throw t)))))))

  (fs-lock! [_ path timeout-ms]
    (try-effect* :fs/lock-failed
      (let [target (fs/path path)]
        (when-let [parent (fs/parent target)] (fs/create-dirs parent))
        (if-let [{:keys [^FileLock lock ^RandomAccessFile raf]} (acquire-lock target timeout-ms)]
          {:lock {:path    (str target)
                  :release (fn [] (.release lock) (.close raf) nil)
                  :handle  lock}}
          (throw (ex-info "timed out acquiring lock"
                          {:path (str target) :timeout-ms timeout-ms}))))))

  (fs-watch! [_ path patterns handler]
    (try-effect* :fs/watch-failed
      (let [dir     (fs/path path)
            service (.newWatchService (FileSystems/getDefault))
            match?  (glob-matcher patterns)
            running (atom true)]
        (.register ^Path dir service
                   (into-array [StandardWatchEventKinds/ENTRY_CREATE
                                StandardWatchEventKinds/ENTRY_MODIFY
                                StandardWatchEventKinds/ENTRY_DELETE]))
        (doto (Thread.
               (fn []
                 (while @running
                   ;; stop! closes the service while this thread is parked in
                   ;; poll — that is a normal shutdown, not a fault
                   (when-let [^WatchKey k (try
                                            (.poll ^WatchService service 200 TimeUnit/MILLISECONDS)
                                            (catch ClosedWatchServiceException _
                                              (reset! running false)
                                              nil))]
                     (doseq [event (.pollEvents k)
                             :let  [child (str (.context event))]
                             :when (match? child)]
                       ;; a throwing handler must not kill the watch thread
                       (try
                         (handler {:kind (keyword (.name (.kind event)))
                                   :path (str (fs/path dir child))})
                         (catch Throwable _ nil)))
                     (.reset k))))
               "hive-system-fs-watch")
          (.setDaemon true)
          (.start))
        {:watcher {:path (str dir)
                   :stop (fn [] (reset! running false) (.close service) nil)}}))))

;; =============================================================================
;; Convenience API (stateless default instance)
;; =============================================================================

(def ^:private default-fs (delay (->FsFilesystem)))

(defn make-filesystem
  "Create an FsFilesystem instance. For DI injection or test doubles."
  []
  (->FsFilesystem))

(defn mkdirs!
  "Create `path` and missing parents; idempotent. Returns Result<{:path}>."
  [path]
  (proto/fs-mkdirs! @default-fs path))

(defn tmpdir!
  "Create a temporary directory. Returns Result<{:path}>."
  ([] (tmpdir! nil))
  ([prefix] (proto/fs-tmpdir! @default-fs prefix)))

(defn atomic-write!
  "Write `content` to `path` via a sibling temp file + atomic rename, so a reader
   never observes a partial file. Returns Result<{:path :bytes}>."
  ([path content] (atomic-write! path content {}))
  ([path content opts] (proto/fs-atomic-write! @default-fs path content opts)))

(defn lock!
  "Acquire an exclusive advisory lock, polling until `timeout-ms`.
   Returns Result<{:lock {:path :release :handle}}>."
  [path timeout-ms]
  (proto/fs-lock! @default-fs path timeout-ms))

(defn watch!
  "Watch `path` for create/modify/delete of children matching `patterns` (globs;
   empty = all), calling `handler` with {:kind :path}.
   Returns Result<{:watcher {:path :stop}}>."
  [path patterns handler]
  (proto/fs-watch! @default-fs path patterns handler))
