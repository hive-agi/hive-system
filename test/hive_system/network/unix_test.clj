(ns hive-system.network.unix-test
  "Real Unix-domain sockets in a temp dir."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-system.network.unix :as unix]
            [hive-system.protocols :as proto])
  (:import [java.nio.channels SocketChannel]
           [java.nio.file Files LinkOption Path]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def ^:dynamic *dir* nil)

(defn- short-tmp-dir
  "A temp dir under /tmp: keeps socket paths far below the 100-byte rule."
  []
  (str (Files/createTempDirectory (Path/of "/tmp" (make-array String 0)) "hs-"
                                  (make-array FileAttribute 0))))

(defn- rm-rf [^String dir]
  (doseq [f (reverse (file-seq (java.io.File. dir)))]
    (.delete ^java.io.File f)))

(use-fixtures :each
  (fn [t]
    (let [d (short-tmp-dir)]
      (try (binding [*dir* d] (t))
           (finally (rm-rf d))))))

(defn- sock [n] (str *dir* "/run/" n ".sock"))

(defn- echo-server [path]
  (:ok (unix/serve-lines! path (fn [line] (str "echo:" line)))))

(defn- ask [path line]
  (let [{:keys [channel]} (:ok (unix/connect! path))]
    (with-open [^SocketChannel ch channel]
      (unix/write-line! ch line)
      (unix/read-line! (unix/line-reader ch) 2000))))

(deftest echo-round-trip
  (let [path (sock "echo")
        srv  (echo-server path)]
    (try
      (is (some? srv))
      (is (= {:ok "echo:hello"} (ask path "hello")))
      (testing "UTF-8 survives the frame"
        (is (= {:ok "echo:olá → ünïcode"} (ask path "olá → ünïcode"))))
      (testing "several frames on one connection"
        (let [{:keys [channel]} (:ok (unix/connect! path))]
          (with-open [^SocketChannel ch channel]
            (let [rdr (unix/line-reader ch)
                  w   (unix/line-writer ch)]
              (w "a") (w "b")
              (is (= [{:ok "echo:a"} {:ok "echo:b"}]
                     [(unix/read-line! rdr 2000) (unix/read-line! rdr 2000)]))))))
      (finally ((:stop! srv))))
    (testing "stop unlinks the socket file"
      (is (not (Files/exists (Path/of path (make-array String 0))
                             (make-array java.nio.file.LinkOption 0)))))))

(deftest socket-and-dir-modes
  (let [path (sock "mode")
        srv  (echo-server path)]
    (try
      (is (= {:ok "rw-------"} (unix/mode-string path)))
      (is (= {:ok "rwx------"} (unix/mode-string (str *dir* "/run"))))
      (finally ((:stop! srv))))))

(deftest stale-path-replaced
  (let [path  (sock "stale")
        first (:ok (unix/bind! path))]
    ;; close the channel but leave the file: a crashed server
    (.close ^java.nio.channels.ServerSocketChannel (:server-socket first))
    (is (= {:ok :stale} (unix/probe path)))
    (let [srv (echo-server path)]
      (try
        (is (:replaced-stale? srv))
        (is (= {:ok "echo:after"} (ask path "after")))
        (finally ((:stop! srv)))))))

(deftest live-path-not-replaced
  (let [path (sock "live")
        srv  (echo-server path)]
    (try
      (let [second (unix/bind! path)]
        (is (= :unix/address-in-use (:error second))))
      (testing "the first server keeps answering"
        (is (= {:ok "echo:still-here"} (ask path "still-here"))))
      (finally ((:stop! srv))))))

(deftest non-socket-path-left-alone
  (let [path (sock "plain")]
    (unix/ensure-dir! (str *dir* "/run"))
    (spit path "data")
    (is (= :unix/not-a-socket (:error (unix/bind! path))))
    (is (= "data" (slurp path)))))

(deftest oversized-frame-refused
  (let [path (sock "big")
        srv  (:ok (unix/serve-lines! path (fn [l] (str "len:" (count l))) {:max-frame-bytes 16}))]
    (try
      (let [{:keys [channel]} (:ok (unix/connect! path))]
        (with-open [^SocketChannel ch channel]
          (testing "the writer refuses before sending"
            (is (= :frame/too-large (:error (unix/write-line! ch (apply str (repeat 17 "x")) 16))))
            (is (= :frame/embedded-newline (:error (unix/write-line! ch "a\nb")))))
          (testing "the reader refuses an oversized frame and recovers at the next line"
            (unix/write-line! ch (apply str (repeat 100 "y")))
            (unix/write-line! ch "ok")
            (is (= {:ok "len:2"} (unix/read-line! (unix/line-reader ch) 2000))))))
      (testing "a reader with a cap reports :frame/too-large"
        (let [{:keys [channel]} (:ok (unix/connect! path))
              big-srv-path (sock "raw")
              raw (:ok (unix/bind! big-srv-path))]
          (.close ^SocketChannel channel)
          (with-open [c ^SocketChannel (:channel (:ok (unix/connect! big-srv-path)))
                      s ^SocketChannel (:channel (:ok (unix/accept! (:server-socket raw))))]
            (unix/write-line! c (apply str (repeat 40 "z")))
            (unix/write-line! c "next")
            (let [rdr (unix/line-reader s {:max-frame-bytes 16 :buf-size 8})]
              (is (= :frame/too-large (:error (unix/read-line! rdr 2000))))
              (is (= {:ok "next"} (unix/read-line! rdr 2000)))))
          (unix/close-server! raw)))
      (finally ((:stop! srv))))))

(deftest read-timeout
  (let [path (sock "quiet")
        raw  (:ok (unix/bind! path))]
    (try
      (with-open [c ^SocketChannel (:channel (:ok (unix/connect! path)))
                  _ ^SocketChannel (:channel (:ok (unix/accept! (:server-socket raw))))]
        (is (= :frame/timeout (:error (unix/read-line! (unix/line-reader c) 50)))))
      (finally (unix/close-server! raw)))))

(deftest peer-principal-is-dir-owner
  (let [path (sock "peer")
        dir  (str *dir* "/run")
        raw  (:ok (unix/bind! path))]
    (try
      (with-open [c ^SocketChannel (:channel (:ok (unix/connect! path)))
                  s ^SocketChannel (:channel (:ok (unix/accept! (:server-socket raw))))]
        (let [peer (unix/peer-principal s)]
          (testing "SO_PEERCRED principal equals the socket dir owner (public API)"
            (is (or (= ::unix/unsupported peer)
                    (.equals (Files/getOwner (Path/of dir (make-array String 0))
                                             (make-array LinkOption 0))
                             peer))))
          (is (true? (unix/peer-allowed? s dir)))
          (testing "a directory that cannot be stat'd refuses (when SO_PEERCRED is supported)"
            (when-not (= ::unix/unsupported peer)
              (is (false? (unix/peer-allowed? s (str *dir* "/no-such-dir"))))))
          (is (some? c))))
      (finally (unix/close-server! raw)))))

(deftest symlinked-dir-refused
  (let [real (str *dir* "/real")
        link (str *dir* "/link")]
    (Files/createDirectories (Path/of real (make-array String 0)) (make-array FileAttribute 0))
    (Files/createSymbolicLink (Path/of link (make-array String 0))
                              (Path/of real (make-array String 0))
                              (make-array FileAttribute 0))
    (is (= :unix/dir-is-symlink (:error (unix/ensure-dir! link))))
    (testing "bind! under a symlinked dir is refused and creates nothing"
      (is (= :unix/dir-is-symlink (:error (unix/bind! (str link "/s.sock")))))
      (is (not (Files/exists (Path/of real (into-array String ["s.sock"]))
                             (make-array LinkOption 0)))))
    (testing "the real directory is accepted"
      (is (= {:ok {:path real}} (unix/ensure-dir! real))))))

(deftest concurrent-bind-on-stale-path
  (dotimes [i 10]
    (let [path    (sock (str "race" i))
          crashed (:ok (unix/bind! path))]
      ;; a crashed server: channel closed, file left behind
      (.close ^java.nio.channels.ServerSocketChannel (:server-socket crashed))
      (is (= {:ok :stale} (unix/probe path)))
      (let [gate    (java.util.concurrent.CountDownLatch. 1)
            starter #(future (.await gate) (unix/bind! path))
            fa      (starter)
            fb      (starter)
            _       (.countDown gate)
            results [@fa @fb]
            winners (filter :ok results)
            losers  (remove :ok results)]
        (try
          (is (= 1 (count winners)) (pr-str results))
          (is (= [:unix/address-in-use] (map :error losers)))
          (testing "the winner keeps its socket file and answers"
            (let [srv (:ok (first winners))]
              (is (= {:ok :live} (unix/probe path)))
              (with-open [c ^SocketChannel (:channel (:ok (unix/connect! path)))]
                (unix/write-line! c "ping")
                ;; the backlog also holds the probes' connections (closed
                ;; at once, so they read EOF); the client's comes after them
                (let [next-line (fn []
                                  (with-open [s ^SocketChannel (:channel (:ok (unix/accept! (:server-socket srv))))]
                                    (unix/read-line! (unix/line-reader s) 2000)))]
                  (is (= {:ok "ping"}
                         (->> (repeatedly 5 next-line)
                              (drop-while #(= :frame/eof (:error %)))
                              first)))))))
          (finally
            (doseq [w winners] (unix/close-server! (:ok w)))))))))

(deftest accept-failure-backs-off
  (testing "the accept loop pauses about accept-backoff-ms after a failed accept"
    (let [calls (atom [])
          open? (atom true)
          t0    (System/nanoTime)]
      (#'unix/accept-loop! #(deref open?)
                           (fn []
                             (swap! calls conj (System/nanoTime))
                             (when (>= (count @calls) 5) (reset! open? false))
                             (throw (java.io.IOException. "boom")))
                           (fn [_] (throw (AssertionError. "no channel was accepted"))))
      (let [ms (/ (- (System/nanoTime) t0) 1e6)]
        (is (= 5 (count @calls)))
        (testing "four pauses between five failures: no busy spin"
          (is (>= ms (* 4 0.8 unix/accept-backoff-ms)) (str ms " ms")))
        (testing "no pause once the channel is closed"
          (is (< ms (* 5 4 unix/accept-backoff-ms)) (str ms " ms"))))))
  (testing "accepted channels are handed on; nil is skipped"
    (let [seen  (atom [])
          queue (atom [nil :a :b])]
      (#'unix/accept-loop! #(boolean (seq @queue))
                           (fn [] (let [x (first @queue)] (swap! queue rest) x))
                           #(swap! seen conj %))
      (is (= [:a :b] @seen)))))

(deftest over-long-path-refused
  (is (= :socket-path/too-long
         (:error (unix/default-socket-path (apply str (repeat 120 "s")))))))

(deftest inetwork-round-trip
  (let [net  (unix/make-network)
        path (sock "net")
        srv  (:ok (proto/net-listen! net path {}))]
    (try
      (is (= "rw-------" (:ok (unix/mode-string path))))
      (let [{:keys [channel]} (:ok (proto/net-connect! net path nil {}))]
        (with-open [^SocketChannel c channel
                    ^SocketChannel s (:channel (:ok (unix/accept! (:server-socket srv))))]
          (is (= {:ok {:bytes-sent 5}} (proto/net-send! net c "hello")))
          (let [res (:ok (proto/net-recv! net s 64 2000))]
            (is (= 5 (:bytes-read res)))
            (is (= "hello" (String. ^bytes (:data res) "UTF-8"))))
          (is (= :net/timeout (:error (proto/net-recv! net s 64 30))))))
      (finally (unix/close-server! srv)))))

;; =============================================================================
;; Review round 2
;; =============================================================================

(deftest probe-of-saturated-live-server-does-not-hang
  (testing "point 1: a live server with a full backlog probes :live within the deadline"
    (let [path (sock "full")
          srv  (:ok (unix/bind! path {:backlog 1}))
          ;; nobody accepts: two connects fill a backlog of 1
          fill (vec (repeatedly 2 #(:channel (:ok (unix/connect! path)))))]
      (try
        (let [probed (future (unix/probe path))
              bound  (future (unix/bind! path))]
          (is (= {:ok :live} (deref probed 5000 ::hung)))
          (is (= :unix/address-in-use (:error (deref bound 5000 {:error ::hung}))))
          (testing "the socket file is still there"
            (is (Files/exists (Path/of path (make-array String 0))
                              (make-array LinkOption 0)))))
        (finally
          (doseq [^SocketChannel c fill] (.close c))
          (unix/close-server! srv))))))

(defn- path-of ^Path [s] (Path/of (str s) (make-array String 0)))
(defn- exists? [s] (Files/exists (path-of s) (make-array LinkOption 0)))

(deftest close-of-old-server-keeps-the-new-socket
  (testing "point 2: close-server! never unlinks a socket that is no longer its own"
    (let [path (sock "swap")
          old  (:ok (unix/bind! path))]
      ;; another starter replaced the path (old file gone, a new one bound)
      (Files/delete (path-of path))
      (let [new (echo-server path)]
        (try
          (is (= {:ok {:path path :unlinked? false}} (unix/close-server! old)))
          (is (exists? path))
          (is (= {:ok "echo:new"} (ask path "new")))
          (finally ((:stop! new))))
        (is (not (exists? path)) "the new server's own stop! unlinks it"))))
  (testing "point 2: close-server! waits for the bind lock"
    (let [path    (sock "locked")
          srv     (:ok (unix/bind! path))
          held    (java.util.concurrent.CountDownLatch. 1)
          release (java.util.concurrent.CountDownLatch. 1)
          holder  (future (#'unix/with-bind-lock (path-of (str path ".lock"))
                                                 (fn [] (.countDown held) (.await release)
                                                   {:ok nil})))]
      (.await held)
      (let [closing (future (unix/close-server! srv))]
        (is (= ::waiting (deref closing 200 ::waiting)))
        (is (exists? path))
        (is (.isOpen ^java.nio.channels.ServerSocketChannel (:server-socket srv)))
        (.countDown release)
        @holder
        (is (= {:ok {:path path :unlinked? true}} (deref closing 5000 ::hung)))
        (is (not (exists? path)))))))

(defn- in-interrupted-thread
  "Run (f) on a fresh thread whose interrupt flag is set first.
   => {:value (f) :interrupted? flag-after}"
  [f]
  (let [out (promise)
        t   (Thread. ^Runnable (fn []
                                 (.interrupt (Thread/currentThread))
                                 (let [v (try (f) (catch Throwable e e))]
                                   (deliver out {:value v
                                                 :interrupted? (.isInterrupted (Thread/currentThread))}))))]
    (.start t)
    (deref out 5000 ::hung)))

(defn- listening? [path]
  (= {:ok :live} (unix/probe path)))

(deftest stop-from-interrupted-thread-closes-the-channel
  (testing "review round 3: stop! on an interrupted thread still closes the server"
    (let [path (sock "intr")
          srv  (echo-server path)]
      (try
        (is (= {:ok "echo:up"} (ask path "up")))
        (let [{:keys [value interrupted?]} (in-interrupted-thread (:stop! srv))]
          (is (= {:path path :unlinked? false :lock-failed? true} (:ok value)) (pr-str value))
          (is (true? interrupted?) "the interrupt flag survives"))
        (is (not (.isOpen ^java.nio.channels.ServerSocketChannel (:server-socket srv))))
        (testing "the accept loop no longer listens: the left file probes :stale"
          (is (not (listening? path)))
          (is (= {:ok :stale} (unix/probe path))))
        (testing "a new bind! on the path replaces the stale file"
          (let [srv2 (echo-server path)]
            (try
              (is (:replaced-stale? srv2))
              (is (= {:ok "echo:again"} (ask path "again")))
              (finally ((:stop! srv2))))))
        (finally
          (when (.isOpen ^java.nio.channels.ServerSocketChannel (:server-socket srv))
            ((:stop! srv))))))))

(deftest close-without-lock-dir-closes-the-channel
  (testing "review round 3: the lock file's directory is gone, close-server! still closes"
    (let [dir  (str *dir* "/gone")
          path (str dir "/s.sock")
          srv  (:ok (unix/bind! path))]
      (is (some? srv))
      ;; the server channel stays bound in the kernel; only the names go
      (Files/delete (path-of path))
      (Files/delete (path-of (str path ".lock")))
      (Files/delete (path-of dir))
      (let [res (unix/close-server! srv)]
        (is (= {:ok {:path path :unlinked? false :lock-failed? true}} res) (pr-str res)))
      (is (not (.isOpen ^java.nio.channels.ServerSocketChannel (:server-socket srv))))
      (testing "a new bind! on the same path succeeds"
        (let [srv2 (echo-server path)]
          (try
            (is (some? srv2))
            (is (= {:ok "echo:back"} (ask path "back")))
            (finally (when srv2 ((:stop! srv2))))))))))

(deftest close-with-lock-file-gone-leaves-the-socket-file
  (testing "review round 3: lock cannot be taken, the socket file is left for the next bind!"
    (let [path (sock "nolock")
          srv  (:ok (unix/bind! path))]
      ;; a .lock that cannot be opened: replace it with a directory
      (Files/delete (path-of (str path ".lock")))
      (Files/createDirectory (path-of (str path ".lock")) (make-array FileAttribute 0))
      (let [res (unix/close-server! srv)]
        (is (= {:ok {:path path :unlinked? false :lock-failed? true}} res) (pr-str res)))
      (is (not (.isOpen ^java.nio.channels.ServerSocketChannel (:server-socket srv))))
      (is (exists? path) "the file is left; never unlinked without the lock")
      (is (= {:ok :stale} (unix/probe path))))))

(deftest dir-created-0700-at-create
  (testing "point 3: every directory ensure-dir! creates is 0700 from the start"
    (let [leaf (str *dir* "/a/b")]
      (is (= {:ok {:path leaf}} (unix/ensure-dir! leaf)))
      (is (= {:ok "rwx------"} (unix/mode-string (str *dir* "/a"))))
      (is (= {:ok "rwx------"} (unix/mode-string leaf))))))

(deftest dir-owner-check-fails-closed
  (testing "point 4: a directory of another user is refused (its owner is not the probe file's)"
    (when-not (= "root" (System/getProperty "user.name"))
      (is (= :unix/dir-not-owned (:error (unix/ensure-dir! "/tmp"))))))
  (testing "point 4: an own directory is refused when the probe file's owner differs"
    (let [d     (str *dir* "/other")
          other (Files/getOwner (path-of "/") (make-array LinkOption 0))]
      (Files/createDirectories (path-of d) (make-array FileAttribute 0))
      (when-not (.equals other (Files/getOwner (path-of d) (make-array LinkOption 0)))
        (with-redefs [unix/process-owner (constantly other)]
          (is (= :unix/dir-not-owned (:error (unix/ensure-dir! d))))))))
  (testing "point 4: when the process owner cannot be learned, the directory is refused"
    (when-not (= "root" (System/getProperty "user.name"))
      (let [d (str *dir* "/ro")]
        (Files/createDirectories (path-of d) (make-array FileAttribute 0))
        (Files/setPosixFilePermissions (path-of d) (PosixFilePermissions/fromString "r-x------"))
        (try
          (is (= :unix/owner-unknown (:error (unix/ensure-dir! d))))
          (is (= {:ok "r-x------"} (unix/mode-string d)) "left untouched")
          (finally
            (Files/setPosixFilePermissions (path-of d) (PosixFilePermissions/fromString "rwx------"))))))))

(defn- mkfifo! [path]
  (let [p (.start (ProcessBuilder. ^"[Ljava.lang.String;" (into-array String ["mkfifo" (str path)])))]
    (zero? (.waitFor p))))

(deftest fifo-is-not-a-socket
  (testing "point 5: a FIFO is :not-socket, refused by bind! and never unlinked"
    (let [path (sock "fifo")]
      (Files/createDirectories (path-of (str *dir* "/run")) (make-array FileAttribute 0))
      (is (mkfifo! path) "mkfifo must succeed for this test to mean anything")
      (when (exists? path)
        (is (= {:ok :not-socket} (unix/probe path)))
        (is (= :unix/not-a-socket (:error (unix/bind! path))))
        (is (exists? path))
        (is (not (Files/getAttribute (path-of path) "unix:isRegularFile"
                                     (make-array LinkOption 0))))))))

(defn- open-client [path]
  (let [ch  (:channel (:ok (unix/connect! path)))]
    {:ch ch :rdr (unix/line-reader ch)}))

(deftest stop-closes-accepted-connections
  (testing "point 6: stop! closes connections the server has accepted"
    (let [path (sock "conns")
          srv  (echo-server path)
          {:keys [^SocketChannel ch rdr]} (open-client path)]
      (try
        (unix/write-line! ch "hi")
        (is (= {:ok "echo:hi"} (unix/read-line! rdr 2000)))
        ((:stop! srv))
        (is (= :frame/eof (:error (unix/read-line! rdr 2000))))
        (is (= 0 ((:connections srv))))
        (finally (.close ch))))))

(deftest connection-cap
  (testing "point 6: a connection over :max-connections is closed at once"
    (let [path (sock "cap")
          srv  (:ok (unix/serve-lines! path (fn [l] (str "echo:" l)) {:max-connections 1}))
          a    (open-client path)
          b    (atom nil)]
      (try
        (unix/write-line! (:ch a) "a")
        (is (= {:ok "echo:a"} (unix/read-line! (:rdr a) 2000)))
        (reset! b (open-client path))
        ;; read without writing: a write to the closed peer could reset
        ;; the stream instead of a clean EOF
        (is (= :frame/eof (:error (unix/read-line! (:rdr @b) 2000))))
        (testing "the first connection is still served"
          (unix/write-line! (:ch a) "a2")
          (is (= {:ok "echo:a2"} (unix/read-line! (:rdr a) 2000))))
        (finally
          (.close ^SocketChannel (:ch a))
          (some-> @b :ch (#(.close ^SocketChannel %)))
          ((:stop! srv)))))))

(deftest idle-connection-closed
  (testing "point 6: :idle-timeout-ms closes a silent connection"
    (let [path (sock "idle")
          srv  (:ok (unix/serve-lines! path (fn [l] (str "echo:" l)) {:idle-timeout-ms 100}))
          {:keys [^SocketChannel ch rdr]} (open-client path)]
      (try
        (unix/write-line! ch "x")
        (is (= {:ok "echo:x"} (unix/read-line! rdr 2000)))
        (is (= :frame/eof (:error (unix/read-line! rdr 3000))))
        (finally (.close ch) ((:stop! srv)))))))
