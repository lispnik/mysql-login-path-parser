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
  "Remove PKCS7 padding from a decrypted block. Returns DATA unchanged if the
padding is not well-formed."
  (let ((len (length data)))
    (if (zerop len)
        data
        (let ((pad (aref data (1- len))))
          (if (and (>= pad 1) (<= pad 16) (<= pad len))
              (subseq data 0 (- len pad))
              data)))))

(defun decrypt-mysql-data (ciphertext aes-key)
  "Decrypt one AES-128-ECB ciphertext chunk and strip PKCS7 padding.
AES-KEY must be the 16-byte folded key."
  (handler-case
      (let ((cipher (iron:make-cipher :aes :mode :ecb :key aes-key))
            (out (make-array (length ciphertext) :element-type '(unsigned-byte 8))))
        (iron:decrypt cipher ciphertext out)
        (strip-pkcs7-padding out))
    (error (e)
      (error 'mysql-login-path-decrypt-error
             :message (format nil "AES decryption failed: ~A" e)))))

(defun decrypt-mylogin-text (file-data)
  "Decrypt the chunked body of a .mylogin.cnf file into the plaintext INI string."
  (let* ((stored-key (subseq file-data +mysql-header-size+ +mysql-total-header-size+))
         (aes-key (fold-aes-key stored-key))
         (len (length file-data))
         (pos +mysql-total-header-size+)
         (out (make-string-output-stream)))
    (loop while (<= (+ pos 4) len)
          do (let ((chunk-len (read-uint32-le file-data pos)))
               (incf pos 4)
               (when (or (null chunk-len)
                         (zerop chunk-len)
                         (> (+ pos chunk-len) len))
                 (return))
               (let ((plain (decrypt-mysql-data
                             (subseq file-data pos (+ pos chunk-len))
                             aes-key)))
                 (incf pos chunk-len)
                 (loop for b across plain do (write-char (code-char b) out)))))
    (get-output-stream-string out)))

(defun unescape-option-value (s)
  "Process MySQL option-file backslash escapes within S.
Recognized: \\b \\t \\n \\r \\s (space) \\\\ \\\". A backslash before any other
character is dropped and that character taken literally."
  (let ((out (make-string-output-stream))
        (len (length s))
        (i 0))
    (loop while (< i len)
          for c = (char s i)
          do (if (and (char= c #\\) (< (1+ i) len))
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
                 (progn (write-char c out) (incf i))))
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