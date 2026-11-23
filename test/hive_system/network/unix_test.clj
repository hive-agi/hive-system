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
