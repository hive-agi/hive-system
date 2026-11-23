(ns hive-system.network.unix
  "Unix-domain-socket adapter for INetwork (STD-04 T1-T5), on JDK NIO only
   (UnixDomainSocketAddress, JDK 16+). No native library, no new dependency.

   Rules it enforces:
     T2  the path comes from hive-system.network.path; the directory is 0700
         and the socket file 0600.
     T3  bind! connect-probes first: a STALE path (nobody answers) is
         unlinked and re-bound, a LIVE one is never unlinked and the bind
         fails, a path that is not a socket is never touched.
     T4  peer-uid reads SO_PEERCRED (jdk.net.ExtendedSocketOptions); nil
         where the JDK does not expose it, so the 0600 mode is the floor.
     T5  frames are newline-delimited UTF-8 lines with a max-frame-bytes cap
         (line-reader / read-line! / write-line!).

   INetwork mapping (UnixNetwork): the socket PATH stands where the protocol
   says host/port — (net-connect! n path nil opts), (net-listen! n path opts).

   Every op returns a hive-dsl Result."
  (:require [hive-dsl.result :as r :refer [try-effect*]]
            [hive-system.network.path :as npath]
            [hive-system.protocols :as proto])
  (:import [java.io ByteArrayOutputStream]
           [java.net ConnectException StandardProtocolFamily UnixDomainSocketAddress]
           [java.nio ByteBuffer]
           [java.nio.channels SelectionKey Selector ServerSocketChannel SocketChannel]
           [java.nio.charset CharacterCodingException CodingErrorAction StandardCharsets]
           [java.nio.file Files LinkOption Path]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def default-max-frame-bytes
  "Default cap of one line frame, newline excluded."
  (* 1024 1024))

(def ^:private no-link-opts (make-array LinkOption 0))
(def ^:private no-attrs (make-array FileAttribute 0))

(defn- ->path ^Path [p]
  (if (instance? Path p) p (Path/of (str p) (make-array String 0))))

(defn- address ^UnixDomainSocketAddress [p]
  (UnixDomainSocketAddress/of (->path p)))

(defn- set-mode! [p mode-str]
  (Files/setPosixFilePermissions (->path p) (PosixFilePermissions/fromString mode-str)))

(defn mode-string
  "The rwx string of `p`, e.g. \"rw-------\". => Result<string>"
  [p]
  (try-effect* :unix/mode-failed
    (PosixFilePermissions/toString (Files/getPosixFilePermissions (->path p) no-link-opts))))

;; =============================================================================
;; Process identity and the default path
;; =============================================================================

(defn current-uid
  "Numeric uid of this process, or nil when the JDK cannot say."
  []
  (try
    (.getUid (com.sun.security.auth.module.UnixSystem.))
    (catch Throwable _ nil)))

(defn default-socket-path
  "T2 path of `service` [and `id`] for this process: reads XDG_RUNTIME_DIR,
   java.io.tmpdir and the uid. => Result<{:path :dir}>"
  ([service] (default-socket-path service nil))
  ([service id]
   (npath/socket-path (into {} (System/getenv))
                      (System/getProperty "java.io.tmpdir")
                      (current-uid)
                      service id)))

;; =============================================================================
;; Directory and probe
;; =============================================================================

(defn ensure-dir!
  "Create `dir` (and parents) and set it 0700. Refuses a directory owned by
   another uid. => Result<{:path}>"
  [dir]
  (let [p (->path dir)]
    (r/let-ok [_ (try-effect* :unix/mkdir-failed (Files/createDirectories p no-attrs))
               owner (try-effect* :unix/stat-failed (Files/getAttribute p "unix:uid" no-link-opts))]
      (let [uid (current-uid)]
        (if (and uid (not= (long owner) (long uid)))
          (r/err :unix/dir-not-owned {:path (str p) :owner owner :uid uid
                                      :message "socket directory belongs to another user"})
          (try-effect* :unix/chmod-failed
            (set-mode! p "rwx------")
            {:path (str p)}))))))

(defn probe
  "What sits at `path`: :absent, :live (a server answers), :stale (a socket
   file nobody answers) or :not-socket (some other file). => Result<keyword>"
  [path]
  (let [p (->path path)]
    (try-effect* :unix/probe-failed
      (cond
        (not (Files/exists p no-link-opts)) :absent
        (not (Files/getAttribute p "unix:isOther" no-link-opts)) :not-socket
        :else (try
                (with-open [_ (SocketChannel/open (address p))] :live)
                (catch ConnectException _ :stale))))))

;; =============================================================================
;; Bind, connect, accept, close
;; =============================================================================

(defn bind!
  "Listen on `path` (T3): ensure the parent dir 0700, connect-probe, unlink
   only a stale socket, bind, chmod 0600. opts: :backlog (default 0 = JDK).
   => Result<{:server-socket ServerSocketChannel :path string}>"
  ([path] (bind! path {}))
  ([path {:keys [backlog] :or {backlog 0}}]
   (let [p (->path path)]
     (r/let-ok [_     (ensure-dir! (.getParent (.toAbsolutePath p)))
                state (probe p)
                _     (case state
                        :live       (r/err :unix/address-in-use
                                           {:path (str p) :message "a live server answers on this socket"})
                        :not-socket (r/err :unix/not-a-socket
                                           {:path (str p) :message "path exists and is not a socket; left alone"})
                        :stale      (try-effect* :unix/unlink-failed (Files/deleteIfExists p))
                        :absent     (r/ok nil))
                ssc   (try-effect* :unix/bind-failed
                        (let [ssc (ServerSocketChannel/open StandardProtocolFamily/UNIX)]
                          (try
                            (.bind ssc (address p) (int backlog))
                            ssc
                            (catch Throwable t (.close ssc) (throw t)))))]
       (try
         (set-mode! p "rw-------")
         (r/ok {:server-socket ssc :path (str p) :replaced-stale? (= state :stale)})
         (catch Exception e
           (.close ^ServerSocketChannel ssc)
           (Files/deleteIfExists p)
           (r/err :unix/chmod-failed {:path (str p) :message (ex-message e)})))))))

(defn connect!
  "Open a client channel to `path`. => Result<{:socket path :channel SocketChannel}>"
  [path]
  (try-effect* :unix/connect-failed
    {:socket (str path) :channel (SocketChannel/open (address path))}))

(defn accept!
  "Block for the next client. => Result<{:channel SocketChannel}>"
  [^ServerSocketChannel ssc]
  (try-effect* :unix/accept-failed
    {:channel (.accept ssc)}))

(defn close-server!
  "Close the server channel and unlink its socket file. => Result<{:path}>"
  [{:keys [^ServerSocketChannel server-socket path]}]
  (try-effect* :unix/close-failed
    (when server-socket (.close server-socket))
    (when path (Files/deleteIfExists (->path path)))
    {:path path}))

;; =============================================================================
;; Peer credentials (T4)
;; =============================================================================

(def ^:private peercred-option
  (delay
    (try
      (let [cls (Class/forName "jdk.net.ExtendedSocketOptions")]
        (.get (.getField cls "SO_PEERCRED") nil))
      (catch Throwable _ nil))))

(defn peer-uid
  "uid of the process at the other end of `ch`, through SO_PEERCRED, or nil
   when the JDK or the OS does not expose it.

   The JDK hands the credential back as a UnixUserPrincipal built from the
   uid; its hashCode is that uid (sun.nio.fs.UnixUserPrincipals$User), and
   the class is checked so no other principal is misread."
  [^SocketChannel ch]
  (when-let [opt @peercred-option]
    (try
      (let [cred (.getOption ch opt)
            user (.user ^jdk.net.UnixDomainPrincipal cred)]
        (when (= "sun.nio.fs.UnixUserPrincipals$User" (.getName (class user)))
          (long (.hashCode user))))
      (catch Throwable _ nil))))

(defn peer-allowed?
  "T4: true when the peer uid equals this process's uid; also true when
   either is unknown (the 0600 file mode is then the only guard)."
  [ch]
  (let [peer (peer-uid ch)
        me   (current-uid)]
    (or (nil? peer) (nil? me) (= (long peer) (long me)))))

;; =============================================================================
;; Raw IO with timeout
;; =============================================================================

(defn- read-into!
  "Read into `buf`; nil timeout blocks. => bytes read, -1 on EOF, ::timeout."
  [^SocketChannel ch ^ByteBuffer buf timeout-ms]
  (if (nil? timeout-ms)
    (.read ch buf)
    (with-open [sel (Selector/open)]
      (.configureBlocking ch false)
      (try
        (.register ch sel SelectionKey/OP_READ)
        (if (pos? (.select sel (long (max 1 timeout-ms))))
          (.read ch buf)
          ::timeout)
        (finally
          (doseq [^SelectionKey k (.keys sel)] (.cancel k))
          (.selectNow sel)
          (.configureBlocking ch true))))))

(defn- write-fully! [^SocketChannel ch ^ByteBuffer buf]
  (loop [n 0]
    (if (.hasRemaining buf)
      (recur (+ n (.write ch buf)))
      n)))

;; =============================================================================
;; Line frames (T5)
;; =============================================================================

(defn- decode-utf8 [^bytes bs]
  (-> StandardCharsets/UTF_8
      .newDecoder
      (.onMalformedInput CodingErrorAction/REPORT)
      (.onUnmappableCharacter CodingErrorAction/REPORT)
      (.decode (ByteBuffer/wrap bs))
      str))

(defn line-reader
  "A stateful newline-delimited UTF-8 frame reader over `ch`.
   opts: :max-frame-bytes (default 1 MiB, newline excluded), :buf-size."
  ([ch] (line-reader ch {}))
  ([ch {:keys [max-frame-bytes buf-size]
        :or {max-frame-bytes default-max-frame-bytes buf-size 8192}}]
   {:channel ch
    :max     max-frame-bytes
    :buf     (doto (ByteBuffer/allocate buf-size) (.flip))
    :acc     (ByteArrayOutputStream.)
    :state   (atom {:discarding? false})}))

(defn read-line!
  "Next frame from a line-reader, without its newline (a trailing CR is
   dropped too). A frame longer than :max-frame-bytes is refused with
   :frame/too-large and skipped up to its newline, so the next call reads
   the frame after it. A frame that is not valid UTF-8 is :frame/bad-utf8.
   EOF is :frame/eof (a partial last line is dropped).
   => Result<string>"
  ([rdr] (read-line! rdr nil))
  ([{:keys [channel max ^ByteBuffer buf ^ByteArrayOutputStream acc state]} timeout-ms]
   (try
     (loop []
       (if (.hasRemaining buf)
         (let [start (.position buf)
               lim   (.limit buf)
               nl    (loop [i start] (cond (= i lim) -1
                                           (= 10 (.get buf (int i))) i
                                           :else (recur (inc i))))
               end   (if (neg? nl) lim nl)
               n     (- end start)]
           (when-not (:discarding? @state)
             (.write acc (.array buf) (+ (.arrayOffset buf) start) n))
           (.position buf (int (if (neg? nl) lim (inc nl))))
           (cond
             (and (neg? nl) (> (.size acc) max))
             (do (.reset acc)
                 (swap! state assoc :discarding? true)
                 (r/err :frame/too-large {:max-frame-bytes max
                                          :message (str "frame exceeds " max " bytes")}))

             (neg? nl) (recur)

             (:discarding? @state)
             (do (swap! state assoc :discarding? false) (recur))

             :else
             (let [bs0 (.toByteArray acc)
                   _   (.reset acc)
                   len (alength bs0)
                   bs  (if (and (pos? len) (= 13 (aget bs0 (dec len))))
                         (java.util.Arrays/copyOf bs0 (dec len))
                         bs0)]
               (if (> (alength bs) max)
                 (r/err :frame/too-large {:max-frame-bytes max
                                          :message (str "frame exceeds " max " bytes")})
                 (try
                   (r/ok (decode-utf8 bs))
                   (catch CharacterCodingException e
                     (r/err :frame/bad-utf8 {:message (ex-message e)})))))))
         (do
           (.clear buf)
           (let [n (read-into! channel buf timeout-ms)]
             (.flip buf)
             (cond
               (= n ::timeout) (r/err :frame/timeout {:timeout-ms timeout-ms})
               (neg? n)        (r/err :frame/eof {:message "peer closed the stream"})
               :else           (recur))))))
     (catch Exception e
       (r/err :frame/read-failed {:class (str (type e)) :message (ex-message e)})))))

(defn write-line!
  "Write `s` as one frame: its UTF-8 bytes and a newline. Refuses a string
   that holds a newline (:frame/embedded-newline) or whose bytes exceed
   `max-frame-bytes` (:frame/too-large).
   => Result<{:bytes-sent}>"
  ([ch s] (write-line! ch s default-max-frame-bytes))
  ([ch ^String s max-frame-bytes]
   (let [bs (.getBytes s StandardCharsets/UTF_8)]
     (cond
       (some #(= 10 %) bs)
       (r/err :frame/embedded-newline {:message "a frame cannot contain a newline"})

       (> (alength bs) max-frame-bytes)
       (r/err :frame/too-large {:bytes (alength bs) :max-frame-bytes max-frame-bytes
                                :message (str "frame is " (alength bs) " bytes, the limit is "
                                              max-frame-bytes)})

       :else
       (try-effect* :frame/write-failed
         (let [buf (ByteBuffer/allocate (inc (alength bs)))]
           (.put buf bs)
           (.put buf (byte 10))
           (.flip buf)
           {:bytes-sent (write-fully! ch buf)}))))))

(defn line-writer
  "A fn of one string that writes it as a frame on `ch` (see write-line!)."
  ([ch] (line-writer ch {}))
  ([ch {:keys [max-frame-bytes] :or {max-frame-bytes default-max-frame-bytes}}]
   (fn [s] (write-line! ch s max-frame-bytes))))

;; =============================================================================
;; A line server (accept loop with the T4 peer check)
;; =============================================================================

(defn serve-lines!
  "Bind `path` and answer each line with (handler line) on a virtual thread
   per connection; a nil answer sends nothing. Peers whose uid differs from
   ours are closed unanswered. opts: :max-frame-bytes, :backlog.
   => Result<{:server-socket :path :stop! (fn [])}>"
  ([path handler] (serve-lines! path handler {}))
  ([path handler opts]
   (r/let-ok [srv (bind! path opts)]
     (let [^ServerSocketChannel ssc (:server-socket srv)
           max   (or (:max-frame-bytes opts) default-max-frame-bytes)
           conn  (fn [^SocketChannel ch]
                   (with-open [ch ch]
                     (when (peer-allowed? ch)
                       (let [rdr (line-reader ch {:max-frame-bytes max})]
                         (loop []
                           (let [res (read-line! rdr)]
                             (cond
                               (r/ok? res)
                               (let [answer (handler (:ok res))]
                                 (when (or (nil? answer) (r/ok? (write-line! ch (str answer) max)))
                                   (recur)))

                               (= :frame/too-large (:error res)) (recur)
                               :else nil)))))))
           loop! (fn []
                   (loop []
                     (when (.isOpen ssc)
                       (when-let [ch (try (.accept ssc) (catch Exception _ nil))]
                         (Thread/startVirtualThread ^Runnable (fn [] (try (conn ch) (catch Exception _ nil)))))
                       (recur))))]
       (Thread/startVirtualThread ^Runnable loop!)
       (r/ok (assoc srv :stop! (fn [] (close-server! srv))))))))

;; =============================================================================
;; INetwork
;; =============================================================================

(defrecord UnixNetwork []
  proto/INetwork

  (net-connect! [_ host _port _opts]
    (connect! host))

  (net-listen! [_ port opts]
    (bind! port (or opts {})))

  (net-send! [_ channel data]
    (try-effect* :net/send-failed
      (let [bs (if (bytes? data) data (.getBytes (str data) StandardCharsets/UTF_8))]
        {:bytes-sent (write-fully! channel (ByteBuffer/wrap bs))})))

  (net-recv! [_ channel buf-size timeout-ms]
    (try
      (let [buf (ByteBuffer/allocate (int buf-size))
            n   (read-into! channel buf timeout-ms)]
        (cond
          (= n ::timeout) (r/err :net/timeout {:timeout-ms timeout-ms})
          (neg? n)        (r/ok {:data (byte-array 0) :bytes-read -1 :eof? true})
          :else           (r/ok {:data (java.util.Arrays/copyOf (.array buf) (int n)) :bytes-read n})))
      (catch Exception e
        (r/err :net/recv-failed {:class (str (type e)) :message (ex-message e)})))))

(defn make-network
  "An INetwork over Unix-domain sockets."
  []
  (->UnixNetwork))
