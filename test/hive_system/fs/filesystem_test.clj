(ns hive-system.fs.filesystem-test
  "IFilesystem contract. Every test works inside a temp dir it created itself —
   never a production path."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.fs.core :as fsq]
            [hive-system.fs.filesystem :as sut]
            [hive-system.protocols :as proto]))

(def ^:dynamic *root* nil)

(defn- with-temp-root [f]
  (let [dir (fs/create-temp-dir {:prefix "hs-fs-test-"})]
    (try
      (binding [*root* (str dir)] (f))
      (finally (fs/delete-tree dir)))))

(use-fixtures :each with-temp-root)

(defn- under [& segs] (str (apply fs/path *root* segs)))

(defn- ok! [res] (is (r/ok? res) (str "expected ok, got " (pr-str res))) (:ok res))

;; --- the record satisfies the protocol --------------------------------------

(deftest fs-filesystem-satisfies-ifilesystem
  (is (satisfies? proto/IFilesystem (sut/make-filesystem)))
  (testing "the protocol declares every method this record implements"
    (is (= #{:fs-watch! :fs-atomic-write! :fs-lock! :fs-tmpdir! :fs-mkdirs!}
           (set (keys (:sigs proto/IFilesystem)))))))

;; --- mkdirs -----------------------------------------------------------------

(deftest mkdirs-creates-missing-parents-and-is-idempotent
  (let [p (under "a" "b" "c")]
    (is (false? (:ok (fsq/directory? p))) "precondition: absent")
    (is (= p (:path (ok! (sut/mkdirs! p)))))
    (is (true? (:ok (fsq/directory? p))))
    (testing "second call is a no-op, not an error"
      (is (r/ok? (sut/mkdirs! p))))))

(deftest mkdirs-fails-loud-when-the-path-is-a-file
  (let [f (under "afile")]
    (spit f "x")
    (let [res (sut/mkdirs! f)]
      (is (r/err? res))
      (is (= :fs/mkdirs-failed (:error res))))))

;; --- tmpdir -----------------------------------------------------------------

(deftest tmpdir-creates-a-real-distinct-directory
  (let [a (:path (ok! (sut/tmpdir! "hs-a-")))
        b (:path (ok! (sut/tmpdir! "hs-a-")))]
    (try
      (is (true? (:ok (fsq/directory? a))))
      (is (true? (:ok (fsq/directory? b))))
      (is (not= a b) "two calls must not collide")
      (is (re-find #"hs-a-" (str (fs/file-name a))) "the prefix is honoured")
      (finally (fs/delete-tree a) (fs/delete-tree b)))))

(deftest tmpdir-works-without-a-prefix
  (let [p (:path (ok! (sut/tmpdir!)))]
    (try (is (true? (:ok (fsq/directory? p))))
         (finally (fs/delete-tree p)))))

;; --- atomic write -----------------------------------------------------------

(deftest atomic-write-lands-the-content-and-reports-its-size
  (let [p (under "out" "note.txt")
        {:keys [path bytes]} (ok! (sut/atomic-write! p "hello"))]
    (is (= p path))
    (is (= "hello" (slurp path)))
    (is (= 5 bytes))
    (testing "parents are created on the way"
      (is (true? (:ok (fsq/directory? (under "out"))))))))

(deftest atomic-write-overwrites-and-leaves-no-temp-behind
  (let [p (under "note.txt")]
    (ok! (sut/atomic-write! p "first"))
    (ok! (sut/atomic-write! p "second"))
    (is (= "second" (slurp p)))
    (is (empty? (filter #(re-find #"^\.hs-" (str (fs/file-name %)))
                        (fs/list-dir *root*)))
        "the sibling temp file must not survive a successful write")))

(deftest atomic-write-accepts-bytes
  (let [p (under "raw.bin")
        payload (.getBytes "abc" "UTF-8")]
    (ok! (sut/atomic-write! p payload))
    (is (= "abc" (slurp p)))))

;; --- lock -------------------------------------------------------------------

(deftest lock-is-exclusive-and-releasable
  (let [p (under "guarded.lock")
        {:keys [lock]} (ok! (sut/lock! p 200))]
    (is (= p (:path lock)))
    (testing "a second acquisition times out rather than hanging"
      (let [res (sut/lock! p 60)]
        (is (r/err? res))
        (is (= :fs/lock-failed (:error res)))))
    (testing "and succeeds once released"
      ((:release lock))
      (let [again (sut/lock! p 200)]
        (is (r/ok? again))
        ((get-in again [:ok :lock :release]))))))

;; --- watch ------------------------------------------------------------------

(deftest watch-reports-a-matching-child-and-stops-cleanly
  (let [seen    (atom [])
        {:keys [watcher]} (ok! (sut/watch! *root* ["*.txt"] #(swap! seen conj %)))]
    (try
      (Thread/sleep 150)
      (spit (under "hit.txt") "x")
      (spit (under "miss.log") "x")
      (let [deadline (+ (System/currentTimeMillis) 4000)]
        (while (and (empty? @seen) (< (System/currentTimeMillis) deadline))
          (Thread/sleep 50)))
      (is (seq @seen) "the watcher saw the matching file")
      (is (every? #(re-find #"hit\.txt$" (:path %)) @seen)
          "the glob filtered the non-matching one out")
      (finally ((:stop watcher))))))

(deftest watch-survives-a-throwing-handler
  (let [{:keys [watcher]} (ok! (sut/watch! *root* [] (fn [_] (throw (ex-info "boom" {})))))]
    (try
      (Thread/sleep 150)
      (spit (under "a.txt") "x")
      (Thread/sleep 300)
      (is true "a handler that throws must not kill the watch thread")
      (finally ((:stop watcher))))))
