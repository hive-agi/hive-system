(ns hive-system.network.unix
  "Unix-domain-socket adapter for INetwork (STD-04 T1-T5), on JDK NIO only
   (UnixDomainSocketAddress, JDK 16+). No native library, no new dependency.

   Rules it enforces:
     T2  the path comes from hive-system.network.path; the directory is 0700
         and the socket file 0600.
         ensure-dir! refuses a socket directory that is a symlink.
     T3  bind! connect-probes first: a STALE path (nobody answers) is
         unlinked and re-bound, a LIVE one is never unlinked and the bind
         fails, a path that is not a socket is never touched. Probe, unlink
         and bind run under an exclusive lock on <socket-path>.lock, so two
         starters cannot unlink each other's fresh socket.
     T4  peer-allowed? compares the SO_PEERCRED principal (public API:
         jdk.net.UnixDomainPrincipal/user) with the owner of the socket
         directory; where SO_PEERCRED is unsupported the 0600 mode is the
         floor.
     T5  frames are newline-delimited UTF-8 lines with a max-frame-bytes cap
         (line-reader / read-line! / write-line!).

   INetwork mapping (UnixNetwork): the socket PATH stands where the protocol
   says host/port — (net-connect! n path nil opts), (net-listen! n path opts).

   Every op returns a hive-dsl Result."
  (:require [hive-dsl.result :as r :refer [try-effect*]]
            [hive-system.network.path :as npath]
            [hive-system.protocols :as proto])
  (:import [java.io ByteArrayOutputStream IOException]
           [java.net ConnectException StandardProtocolFamily UnixDomainSocketAddress]
           [java.nio ByteBuffer]
           [java.nio.channels FileChannel SelectionKey Selector ServerSocketChannel SocketChannel]
           [java.nio.charset CharacterCodingException CodingErrorAction StandardCharsets]
           [java.nio.file Files LinkOption Path StandardOpenOption]
           [java.nio.file.attribute BasicFileAttributes FileAttribute PosixFilePermissions
            UserPrincipal]
           [java.util Set]
           [java.util.concurrent ConcurrentHashMap]
           [java.util.function Function]
           [jdk.net ExtendedSocketOptions UnixDomainPrincipal]))

;; Copyright (C) 2026 Pedro Gomes Branquinho (BuddhiLW) <pedrogbranquinho@gmail.com>
;;
;; SPDX-License-Identifier: MIT

(def default-max-frame-bytes
  "Default cap of one line frame, newline excluded."
  (* 1024 1024))

(def ^:private no-link-opts (make-array LinkOption 0))
(def ^:private nofollow (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))

(def accept-backoff-ms
  "Pause of the serve-lines! accept loop after a failed accept while the
   server channel is still open, so a persistent failure does not spin."
  50)
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
  "Numeric uid of this process, or nil when the JDK cannot say.

   Used ONLY to name the fallback socket directory (<tmpdir>/hive-<uid>,
   the T2 rule), where a number is unavoidable: no public JDK API returns
   the numeric uid, so com.sun.security.auth.module.UnixSystem (exported
   by the jdk.security.auth module) stays here. Security checks never use
   it; ensure-dir! compares owner principals instead (see process-owner)."
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

(def ^:private dir-attrs
  "rwx------ at create time, so the directory never exists wider than 0700
   (the umask can only narrow it)."
  (into-array FileAttribute [(PosixFilePermissions/asFileAttribute
                              (PosixFilePermissions/fromString "rwx------"))]))

(defn- process-owner
  "The UserPrincipal that owns a file this process creates in `dir` right
   now (created 0600, deleted at once). Public API only: no numeric uid,
   no vendor class. Throws when the file cannot be created, so a caller
   that cannot learn who it is refuses (fails closed)."
  ^UserPrincipal [^Path dir]
  (let [f (Files/createTempFile dir ".owner-" ".tmp"
                                (into-array FileAttribute [(PosixFilePermissions/asFileAttribute
                                                            (PosixFilePermissions/fromString "rw-------"))]))]
    (try
      (Files/getOwner f nofollow)
      (finally (Files/deleteIfExists f)))))

(defn ensure-dir!
  "Create `dir` (and parents) with mode 0700 given AT CREATE (no window at
   the umask mode), then chmod it 0700. Refuses a directory that is a
   symlink (checked with NOFOLLOW_LINKS before and after the create) and
   one whose owner is not the owner of a file this process has just
   created in it (process-owner). When that owner cannot be learned the
   directory is refused too (fail closed: :unix/owner-unknown).
   => Result<{:path}>"
  [dir]
  (let [p        (->path dir)
        symlink? (fn [] (Files/isSymbolicLink p))
        refuse   (fn [] (r/err :unix/dir-is-symlink
                               {:path (str p) :message "socket directory is a symlink; refused"}))]
    (if (symlink?)
      (refuse)
      (r/let-ok [_ (try-effect* :unix/mkdir-failed (Files/createDirectories p dir-attrs))]
        (if (or (symlink?) (not (Files/isDirectory p nofollow)))
          (refuse)
          (r/let-ok [owner (try-effect* :unix/stat-failed (Files/getOwner p nofollow))
                     me    (try-effect* :unix/owner-unknown (process-owner p))]
            (if-not (.equals ^UserPrincipal owner me)
              (r/err :unix/dir-not-owned {:path (str p) :owner (str owner) :process-owner (str me)
                                          :message "socket directory belongs to another user"})
              (try-effect* :unix/chmod-failed
                (set-mode! p "rwx------")
                {:path (str p)}))))))))

(def default-probe-timeout-ms
  "Deadline of the probe's connect. Past it the path counts as :live: a
   slow or saturated live server must never be unlinked."
  500)

(def ^:private s-ifmt 0170000)
(def ^:private s-ifsock 0140000)

(defn- socket-file?
  "True when `p` itself (not a symlink target) is a socket: S_IFSOCK in
   the unix:mode attribute. A FIFO, a device or a symlink is not."
  [^Path p]
  (= s-ifsock (bit-and (long (Files/getAttribute p "unix:mode" nofollow)) s-ifmt)))

(defn- connect-state
  "Non-blocking connect to `p` with a deadline: :live when it connects (or
   is still pending at the deadline, or the kernel says the backlog is
   full), :stale only when the kernel refuses (ECONNREFUSED: no listener),
   :absent when the file vanished meanwhile."
  [^Path p timeout-ms]
  (with-open [ch (SocketChannel/open StandardProtocolFamily/UNIX)]
    (.configureBlocking ch false)
    (try
      (if (.connect ch (address p))
        :live
        (with-open [sel (Selector/open)]
          (.register ch sel SelectionKey/OP_CONNECT)
          ;; finishConnect throws ConnectException on a refusal; a pending
          ;; connect at the deadline is a live (slow) server.
          (when (pos? (.select sel (long (max 1 timeout-ms))))
            (.finishConnect ch))
          :live))
      (catch ConnectException _ :stale)
      (catch IOException _
        ;; EAGAIN (full backlog) or any other failure that is not a proven
        ;; refusal: never call it stale.
        (if (Files/exists p nofollow) :live :absent)))))

(defn probe
  "What sits at `path`: :absent, :live (a server answers, or does not
   answer within the deadline), :stale (a socket file whose connect is
   refused: nobody listens) or :not-socket (anything that is not a socket
   by S_IFSOCK, a symlink included). The connect is non-blocking with a
   deadline (opts :timeout-ms, default default-probe-timeout-ms), so a
   live server with a full backlog or stalled accepts cannot hang the
   caller. => Result<keyword>"
  ([path] (probe path {}))
  ([path {:keys [timeout-ms] :or {timeout-ms default-probe-timeout-ms}}]
   (let [p (->path path)]
     (try-effect* :unix/probe-failed
       (cond
         (not (Files/exists p nofollow)) :absent
         (not (socket-file? p))          :not-socket
         :else                           (connect-state p timeout-ms))))))

;; =============================================================================
;; Bind, connect, accept, close
;; =============================================================================

(def ^:private jvm-bind-locks
  "In-JVM lock per lock-file path: a FileLock is held per JVM, so two
   threads of one JVM must also be serialized here (a second FileChannel
   lock on the same file in the same JVM throws instead of waiting).

   It grows without bound, by design: one small ReentrantLock per distinct
   socket path ever bound or closed in this JVM. Evicting an entry would
   let two threads hold two different locks for the same path (one took
   the old lock, the next a fresh one), which reopens the unlink race the
   lock exists to close. A process binds a handful of paths, so the map
   stays tiny."
  (ConcurrentHashMap.))

(defn- jvm-bind-lock ^java.util.concurrent.locks.ReentrantLock [^String k]
  (.computeIfAbsent ^ConcurrentHashMap jvm-bind-locks k
                    (reify Function
                      (apply [_ _] (java.util.concurrent.locks.ReentrantLock.)))))

(defn- with-bind-lock
  "Run (f) holding an exclusive lock on `lock-path`: the in-JVM lock, then a
   FileChannel lock on the file (created 0600), so a starter in another
   process waits too. The lock file <socket-path>.lock is never removed, by
   design: unlinking it would let a third starter create and lock a fresh
   inode while the second still holds the lock on the old one, so two
   starters would run probe/unlink/bind at once. It is an empty 0600 file
   in the 0700 socket directory and costs nothing. => (f)'s Result."
  [^Path lock-path f]
  (let [jl (jvm-bind-lock (str (.toAbsolutePath lock-path)))]
    (.lock jl)
    (try
      (r/let-ok [^FileChannel fc
                 (try-effect* :unix/lock-failed
                   (FileChannel/open lock-path
                                     (doto (java.util.HashSet.)
                                       (.add StandardOpenOption/CREATE)
                                       (.add StandardOpenOption/WRITE)
                                       (.add LinkOption/NOFOLLOW_LINKS))
                                     (into-array FileAttribute
                                                 [(PosixFilePermissions/asFileAttribute
                                                   (PosixFilePermissions/fromString "rw-------"))])))]
        (try
          (r/let-ok [_ (try-effect* :unix/lock-failed (.lock fc))]
            (f))
          (finally (.close fc))))
      (finally (.unlock jl)))))

(defn- file-key-of
  "Identity (dev, inode) of the file at `p` itself, or nil when absent."
  [^Path p]
  (try
    (.fileKey (Files/readAttributes p BasicFileAttributes
                                    ^"[Ljava.nio.file.LinkOption;" nofollow))
    (catch IOException _ nil)))

(defn bind!
  "Listen on `path` (T3): ensure the parent dir 0700, then, holding an
   exclusive lock on <path>.lock, connect-probe, unlink only a stale socket
   and bind; chmod 0600. opts: :backlog (default 0 = JDK), :probe-timeout-ms
   (default default-probe-timeout-ms; a probe past it counts as :live).
   :file-key in the answer is the bound socket file's identity (dev, inode);
   close-server! unlinks the path only while it still carries that key.
   => Result<{:server-socket ServerSocketChannel :path string :file-key :replaced-stale?}>"
  ([path] (bind! path {}))
  ([path {:keys [backlog probe-timeout-ms]
          :or {backlog 0 probe-timeout-ms default-probe-timeout-ms}}]
   (let [p    (.toAbsolutePath (->path path))
         lock (->path (str p ".lock"))]
     (r/let-ok [_ (ensure-dir! (.getParent p))]
       (with-bind-lock lock
         (fn []
           (r/let-ok [state (probe p {:timeout-ms probe-timeout-ms})
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
               (r/ok {:server-socket   ssc
                      :path            (str p)
                      :file-key        (file-key-of p)
                      :replaced-stale? (= state :stale)})
               (catch Exception e
                 (.close ^ServerSocketChannel ssc)
                 (Files/deleteIfExists p)
                 (r/err :unix/chmod-failed {:path (str p) :message (ex-message e)}))))))))))

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
  "Unlink the socket file, then close the server channel, holding the same
   <path>.lock as bind!. The file is unlinked only while it is still THIS
   server's socket (its :file-key, dev+inode, matches): once another
   starter has replaced the path, the new live socket is left alone.
   Unlinking before the close means no starter can see this socket as
   :stale in between. => Result<{:path :unlinked?}>"
  [{:keys [^ServerSocketChannel server-socket path file-key]}]
  (if-not path
    (try-effect* :unix/close-failed
      (when server-socket (.close server-socket))
      {:path nil :unlinked? false})
    (let [p (.toAbsolutePath (->path path))]
      (with-bind-lock (->path (str p ".lock"))
        (fn []
          (try-effect* :unix/close-failed
            (let [mine?     (and (some? file-key) (= file-key (file-key-of p)))
                  unlinked? (boolean (and mine? (Files/deleteIfExists p)))]
              (when server-socket (.close server-socket))
              {:path path :unlinked? unlinked?})))))))

;; =============================================================================
;; Peer credentials (T4)
;; =============================================================================

(defn peer-principal
  "The UserPrincipal of the process at the other end of `ch`, read through
   SO_PEERCRED (jdk.net.UnixDomainPrincipal/user, public API), or
   ::unsupported when the JDK or the OS does not expose the option.
   Throws when the option is supported but reading it fails."
  [^SocketChannel ch]
  (let [opt ExtendedSocketOptions/SO_PEERCRED]
    (if (.contains (.supportedOptions ch) opt)
      (.user ^UnixDomainPrincipal (.getOption ch opt))
      ::unsupported)))

(defn peer-allowed?
  "T4: true when the SO_PEERCRED principal of `ch` equals (by .equals) the
   owner of the socket directory `dir` (java.nio.file.Files/getOwner), or
   when SO_PEERCRED is unsupported (the 0600 file mode is then the floor).
   Any failure to read either side refuses."
  [ch dir]
  (try
    (let [peer (peer-principal ch)]
      (or (= ::unsupported peer)
          (let [^UserPrincipal owner (Files/getOwner (->path dir) nofollow)]
            (boolean (and peer (.equals owner peer))))))
    (catch Throwable _ false)))

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

(defn- accept-loop!
  "While (open?) is true, call (accept!) and hand each non-nil channel to
   (on-channel ch). When accept! throws while (open?) still holds, sleep
   accept-backoff-ms before trying again, so a persistent failure (e.g.
   EMFILE) does not spin a core; a throw after close ends the loop."
  [open? accept! on-channel]
  (loop []
    (when (open?)
      (let [ch (try (accept!) (catch Exception _ ::failed))]
        (cond
          (= ::failed ch)
          (when (open?)
            (try (Thread/sleep (long accept-backoff-ms))
                 (catch InterruptedException _ nil)))

          (some? ch)
          (on-channel ch)))
      (recur))))

(def default-max-connections
  "Default cap of connections serve-lines! serves at once; one accepted
   over the cap is closed at once, unanswered."
  256)

(defn- serve-connection
  "Answer the lines of `ch` until EOF, an error or the idle deadline."
  [^SocketChannel ch dir handler max idle-timeout-ms]
  (when (peer-allowed? ch dir)
    (let [rdr (line-reader ch {:max-frame-bytes max})]
      (loop []
        (let [res (read-line! rdr idle-timeout-ms)]
          (cond
            (r/ok? res)
            (let [answer (handler (:ok res))]
              (when (or (nil? answer) (r/ok? (write-line! ch (str answer) max)))
                (recur)))

            (= :frame/too-large (:error res)) (recur)
            :else nil))))))

(defn serve-lines!
  "Bind `path` and answer each line with (handler line) on a virtual thread
   per connection; a nil answer sends nothing. Peers whose SO_PEERCRED
   principal is not the owner of the socket directory are closed
   unanswered. A failed accept while the server is open pauses
   accept-backoff-ms before the next one.

   opts: :max-frame-bytes, :backlog, :probe-timeout-ms (see bind!),
         :max-connections (default default-max-connections): a connection
           accepted while that many are open is closed at once,
         :idle-timeout-ms (default nil = none): a connection that sends no
           byte for that long is closed.

   stop! unlinks the socket (see close-server!), closes the server channel
   and then every accepted connection still open, which ends their
   virtual threads (a blocked read fails on the closed channel).
   => Result<{:server-socket :path :stop! (fn []) :connections (fn [] n)}>"
  ([path handler] (serve-lines! path handler {}))
  ([path handler {:keys [max-frame-bytes max-connections idle-timeout-ms] :as opts}]
   (r/let-ok [srv (bind! path opts)]
     (let [^ServerSocketChannel ssc (:server-socket srv)
           dir      (.getParent (->path (:path srv)))
           max      (or max-frame-bytes default-max-frame-bytes)
           cap      (long (or max-connections default-max-connections))
           ^Set open-chs (ConcurrentHashMap/newKeySet)
           stopped? (atom false)
           close!   (fn [^SocketChannel ch] (try (.close ch) (catch IOException _ nil)))
           on-ch    (fn [^SocketChannel ch]
                      (if (>= (.size open-chs) cap)
                        (close! ch)
                        (do
                          (.add open-chs ch)
                          ;; stop! may have swept the set before this add
                          (if @stopped?
                            (do (.remove open-chs ch) (close! ch))
                            (Thread/startVirtualThread
                             ^Runnable (fn []
                                         (try
                                           (serve-connection ch dir handler max idle-timeout-ms)
                                           (catch Exception _ nil)
                                           (finally
                                             (.remove open-chs ch)
                                             (close! ch)))))))))
           stop!    (fn []
                      (reset! stopped? true)
                      (let [res (close-server! srv)]
                        (doseq [ch (vec open-chs)] (close! ch))
                        (.clear open-chs)
                        res))]
       (Thread/startVirtualThread
        ^Runnable (fn [] (accept-loop! #(.isOpen ssc) #(.accept ssc) on-ch)))
       (r/ok (assoc srv
                    :stop! stop!
                    :connections (fn [] (.size open-chs))))))))

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
