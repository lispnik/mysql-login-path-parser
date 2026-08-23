(in-package #:mysql-login-path-parser)

;;; MySQL .mylogin.cnf format (from MySQL source code):
;;; - 4 bytes unused header (version)
;;; - 20 bytes stored key (LOGIN_KEY_LEN)
;;; - Then a sequence of chunks, each:
;;;     - 4 bytes little-endian length
;;;     - <length> bytes AES-128-ECB ciphertext (PKCS7 padded)
;;; The 16-byte AES key is derived from the 20-byte stored key by
;;; XOR-folding (my_aes_create_key): rkey[i mod 16] ^= key[i].
;;; Decrypted plaintext is ordinary my.cnf-style INI text.

(define-condition mysql-login-path-error (error)
  ((message :initarg :message :reader mysql-login-path-error-message))
  (:report (lambda (condition stream)
             (format stream "MySQL login path error: ~A"
                     (mysql-login-path-error-message condition)))))

(define-condition mysql-login-path-parse-error (mysql-login-path-error)
  ()
  (:report (lambda (condition stream)
             (format stream "MySQL login path parse error: ~A"
                     (mysql-login-path-error-message condition)))))

(define-condition mysql-login-path-decrypt-error (mysql-login-path-error)
  ()
  (:report (lambda (condition stream)
             (format stream "MySQL login path decrypt error: ~A"
                     (mysql-login-path-error-message condition)))))

(defconstant +mysql-header-size+ 4
  "Size of unused header in .mylogin.cnf")

(defconstant +mysql-key-size+ 20
  "Size of stored key in .mylogin.cnf (LOGIN_KEY_LEN from MySQL source)")

(defconstant +mysql-total-header-size+ (+ +mysql-header-size+ +mysql-key-size+)
  "Total header size: unused header + key")

(defconstant +mysql-aes-key-size+ 16
  "AES-128 key size in bytes")

(defconstant +mysql-aes-block-size+ 16
  "AES block size in bytes")

(defun read-uint32-le (data offset)
  "Read 32-bit little-endian integer from byte array"
  (when (>= (length data) (+ offset 4))
    (+ (aref data offset)
       (ash (aref data (+ offset 1)) 8)
       (ash (aref data (+ offset 2)) 16)
       (ash (aref data (+ offset 3)) 24))))

(defun read-null-terminated-string (data start)
  "Read null-terminated string from byte array, return (values string next-position)"
  (when (< start (length data))
    (let ((end (position 0 data :start start)))
      (if end
          (values (map 'string (lambda (b)
                                 (if (and (>= b 32) (<= b 126))
                                     (code-char b)
                                     #\?))  ; Replace non-printable with ?
                       (subseq data start end))
                  (1+ end))
          (values (map 'string (lambda (b)
                                 (if (and (>= b 32) (<= b 126))
                                     (code-char b)
                                     #\?))
                       (subseq data start))
                  (length data))))))

(defun fold-aes-key (stored-key)
  "Fold the 20-byte stored key into a 16-byte AES-128 key via XOR.
Mirrors MySQL's my_aes_create_key: rkey[i mod 16] ^= key[i]."
  (let ((rkey (make-array +mysql-aes-key-size+
                          :element-type '(unsigned-byte 8)
                          :initial-element 0)))
    (dotimes (i (length stored-key))
      (let ((idx (mod i +mysql-aes-key-size+)))
        (setf (aref rkey idx) (logxor (aref rkey idx) (aref stored-key i)))))
    rkey))

(defun read-aes-key-from-file (filepath)
  "Extract and fold the AES key from .mylogin.cnf into a 16-byte AES-128 key."
  (with-open-file (stream filepath :element-type '(unsigned-byte 8))
    (let ((file-length (file-length stream)))
      (when (< file-length +mysql-total-header-size+)
        (error 'mysql-login-path-parse-error
               :message (format nil "File too small: ~A bytes, need at least ~A"
                               file-length +mysql-total-header-size+)))

      (let ((header-and-key (make-array +mysql-total-header-size+
                                       :element-type '(unsigned-byte 8))))
        (read-sequence header-and-key stream)
        (fold-aes-key (subseq header-and-key +mysql-header-size+
                              +mysql-total-header-size+))))))

(defun strip-pkcs7-padding (data)
  "Remove PKCS7 padding from a decrypted block.
Signals MYSQL-LOGIN-PATH-DECRYPT-ERROR unless every padding byte is well-formed.
Checking all of them -- not just the last -- doubles as an integrity check that
the AES key was derived correctly, since a wrong key yields random bytes that
pass a last-byte-only test about 6% of the time per chunk."
  (let ((len (length data)))
    (when (zerop len)
      (return-from strip-pkcs7-padding data))
    (let ((pad (aref data (1- len))))
      (unless (and (>= pad 1) (<= pad +mysql-aes-block-size+) (<= pad len))
        (error 'mysql-login-path-decrypt-error
               :message (format nil "Invalid PKCS7 padding byte: ~A" pad)))
      (loop for i from (- len pad) below len
            unless (= (aref data i) pad)
              do (error 'mysql-login-path-decrypt-error
                        :message (format nil "Malformed PKCS7 padding: expected ~A at offset ~A, got ~A"
                                         pad i (aref data i))))
      (subseq data 0 (- len pad)))))

(defun decrypt-mysql-data (ciphertext aes-key)
  "Decrypt one AES-128-ECB ciphertext chunk and strip PKCS7 padding.
AES-KEY must be the 16-byte folded key."
  ;; Ironclad's ECB decrypt silently processes only whole blocks, leaving the
  ;; trailing bytes of OUT unwritten (and, per ANSI, unspecified). Reject a
  ;; short chunk up front rather than letting that garbage into the plaintext.
  (let ((len (length ciphertext)))
    (unless (and (plusp len) (zerop (mod len +mysql-aes-block-size+)))
      (error 'mysql-login-path-decrypt-error
             :message (format nil "Ciphertext length ~A is not a positive multiple of the ~A-byte AES block size"
                              len +mysql-aes-block-size+))))
  (handler-case
      (let ((cipher (iron:make-cipher :aes :mode :ecb :key aes-key))
            (out (make-array (length ciphertext) :element-type '(unsigned-byte 8))))
        (iron:decrypt cipher ciphertext out)
        (strip-pkcs7-padding out))
    ;; Our own errors (bad padding) pass through unwrapped.
    (mysql-login-path-error (e)
      (error e))
    (error (e)
      (error 'mysql-login-path-decrypt-error
             :message (format nil "AES decryption failed: ~A" e)))))

(defun decrypt-mylogin-text (file-data)
  "Decrypt the chunked body of a .mylogin.cnf file into the plaintext INI string.
mysql_config_editor writes the plaintext as UTF-8, so the decrypted bytes are
accumulated and decoded as a whole -- decoding byte-by-byte would mangle any
non-ASCII user name or password."
  (let* ((stored-key (subseq file-data +mysql-header-size+ +mysql-total-header-size+))
         (aes-key (fold-aes-key stored-key))
         (len (length file-data))
         (pos +mysql-total-header-size+)
         (out (make-array 0 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer t)))
    ;; A well-formed body ends exactly on a chunk boundary. Anything else --
    ;; a partial length header, a zero length, a chunk running past EOF -- is a
    ;; corrupt or truncated file, and is reported rather than quietly ending the
    ;; loop with whatever was decoded so far.
    (loop
      (let ((remaining (- len pos)))
        (when (zerop remaining)
          (return))
        (when (< remaining 4)
          (error 'mysql-login-path-parse-error
                 :message (format nil "Truncated chunk header at offset ~A: ~A byte(s) left, need 4"
                                  pos remaining)))
        (let ((chunk-len (read-uint32-le file-data pos)))
          (incf pos 4)
          (when (zerop chunk-len)
            (error 'mysql-login-path-parse-error
                   :message (format nil "Zero-length chunk at offset ~A" (- pos 4))))
          (when (> (+ pos chunk-len) len)
            (error 'mysql-login-path-parse-error
                   :message (format nil "Truncated chunk at offset ~A: declared ~A bytes, only ~A available"
                                    (- pos 4) chunk-len (- len pos))))
          (let ((plain (decrypt-mysql-data
                        (subseq file-data pos (+ pos chunk-len))
                        aes-key)))
            (incf pos chunk-len)
            (loop for b across plain do (vector-push-extend b out))))))
    (babel:octets-to-string (coerce out '(simple-array (unsigned-byte 8) (*)))
                            :encoding :utf-8 :errorp nil)))

(defun unescape-option-value (s)
  "Process MySQL option-file backslash escapes within S.
Recognized: \\b \\t \\n \\r \\s (space) \\\\ \\\". A backslash before any other
character is dropped and that character taken literally."
  (let ((out (make-string-output-stream))
        (len (length s))
        (i 0))
    ;; NB: a `for c = ...` variable-clause after `while` is non-conforming
    ;; (ANSI requires variable-clauses first), so bind C in the body instead.
    (loop while (< i len)
          do (let ((c (char s i)))
               (if (and (char= c #\\) (< (1+ i) len))
                   (progn
                     (write-char (case (char s (1+ i))
                                   (#\b #\Backspace)
                                   (#\t #\Tab)
                                   (#\n #\Newline)
                                   (#\r #\Return)
                                   (#\s #\Space)
                                   (#\\ #\\)
                                   (#\" #\")
                                   (t (char s (1+ i))))
                                 out)
                     (incf i 2))
                   (progn (write-char c out) (incf i)))))
    (get-output-stream-string out)))

(defun unquote-value (value)
  "Strip a single pair of surrounding double quotes from VALUE and process
MySQL backslash escapes within them. Unquoted values are returned literally."
  (let ((len (length value)))
    (if (and (>= len 2)
             (char= (char value 0) #\")
             (char= (char value (1- len)) #\"))
        (unescape-option-value (subseq value 1 (1- len)))
        value)))

(defun parse-ini-text (text)
  "Parse my.cnf-style INI TEXT into login paths: a list of
(path-name . ((key . value) ...))."
  (let ((paths '())
        (current-name nil)
        (current-pairs '()))
    (flet ((flush ()
             (when current-name
               (push (cons current-name (nreverse current-pairs)) paths))
             (setf current-name nil
                   current-pairs '())))
      (with-input-from-string (stream text)
        (loop for line = (read-line stream nil nil)
              while line
              do (let* ((trimmed (string-trim '(#\Space #\Tab #\Return #\Newline) line))
                        (tlen (length trimmed)))
                   (cond
                     ((zerop tlen) nil)
                     ;; Comments
                     ((member (char trimmed 0) '(#\# #\;)) nil)
                     ;; Section header [name]
                     ((and (char= (char trimmed 0) #\[)
                           (char= (char trimmed (1- tlen)) #\]))
                      (flush)
                      (setf current-name (subseq trimmed 1 (1- tlen))))
                     ;; key = value
                     (t
                      (let ((eq-pos (position #\= trimmed)))
                        (when (and eq-pos current-name)
                          (let ((key (string-trim '(#\Space #\Tab)
                                                  (subseq trimmed 0 eq-pos)))
                                (val (unquote-value
                                      (string-trim '(#\Space #\Tab)
                                                   (subseq trimmed (1+ eq-pos))))))
                            (push (cons key val) current-pairs)))))))))
      (flush))
    (nreverse paths)))

(defun parse-mylogin-cnf (filepath)
  "Parse MySQL .mylogin.cnf file using native AES decryption.
Returns a list of (path-name . ((key . value) ...))."
  (handler-case
      (progn
        (unless (probe-file filepath)
          (error 'mysql-login-path-parse-error
                 :message (format nil "File not found: ~A" filepath)))

        (with-open-file (stream filepath :element-type '(unsigned-byte 8))
          (let* ((file-length (file-length stream))
                 (file-data (make-array file-length :element-type '(unsigned-byte 8))))

            (read-sequence file-data stream)

            (when (< file-length +mysql-total-header-size+)
              (error 'mysql-login-path-parse-error
                     :message "File too small to contain valid MySQL login data"))

            (when (= file-length +mysql-total-header-size+)
              (return-from parse-mylogin-cnf '()))  ; Header only, no entries

            (parse-ini-text (decrypt-mylogin-text file-data)))))

    (mysql-login-path-error (e)
      ;; Re-raise our own errors
      (error e))
    (error (e)
      ;; Wrap other errors
      (error 'mysql-login-path-parse-error
             :message (format nil "Unexpected error: ~A" e)))))

(defun get-login-path-credentials (login-path &optional (config-file "~/.mylogin.cnf"))
  "Get credentials for a specific login path"
  (let ((expanded-path (probe-file config-file)))
    (when expanded-path
      (handler-case
          (let ((all-paths (parse-mylogin-cnf expanded-path)))
            (cdr (assoc login-path all-paths :test #'string=)))
        (mysql-login-path-error ()
          ;; Silently return nil for parsing errors (allows fallback)
          nil)))))

(defun list-login-paths (&optional (config-file "~/.mylogin.cnf"))
  "List all available login paths"
  (let ((expanded-path (probe-file config-file)))
    (when expanded-path
      (handler-case
          (mapcar #'car (parse-mylogin-cnf expanded-path))
        (mysql-login-path-error ()
          ;; Return empty list for parsing errors
          '())))))
