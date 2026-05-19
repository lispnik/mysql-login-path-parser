(in-package #:mysql-login-path-parser)

;;; MySQL .mylogin.cnf format (from MySQL source code):
;;; - 4 bytes unused header
;;; - 20 bytes AES encryption key (stored in plaintext!)
;;; - Rest is AES-128-ECB encrypted data using that key

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
  "Size of AES key in .mylogin.cnf (LOGIN_KEY_LEN from MySQL source)")

(defconstant +mysql-total-header-size+ (+ +mysql-header-size+ +mysql-key-size+)
  "Total header size: unused header + key")

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

(defun read-aes-key-from-file (filepath)
  "Extract the 20-byte AES key from .mylogin.cnf file (bytes 4-23)"
  (with-open-file (stream filepath :element-type '(unsigned-byte 8))
    (let ((file-length (file-length stream)))
      (when (< file-length +mysql-total-header-size+)
        (error 'mysql-login-path-parse-error
               :message (format nil "File too small: ~A bytes, need at least ~A"
                               file-length +mysql-total-header-size+)))

      (let ((header-and-key (make-array +mysql-total-header-size+
                                       :element-type '(unsigned-byte 8))))
        (read-sequence header-and-key stream)
        (subseq header-and-key +mysql-header-size+ +mysql-total-header-size+)))))

(defun decrypt-mysql-data (encrypted-data aes-key)
  "Decrypt MySQL data using AES-128-ECB with Ironclad"
  (handler-case
      (let ((cipher (iron:make-cipher :aes :mode :ecb :key aes-key)))
        ;; AES requires input to be multiple of 16 bytes
        (let* ((data-length (length encrypted-data))
               (padded-length (* (ceiling data-length 16) 16))
               (padded-data (make-array padded-length
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
          ;; Copy original data
          (replace padded-data encrypted-data)

          ;; Decrypt
          (let ((decrypted (make-array padded-length
                                      :element-type '(unsigned-byte 8))))
            (iron:decrypt cipher padded-data decrypted)
            ;; Return only the original length (remove padding)
            (subseq decrypted 0 data-length))))
    (error (e)
      (error 'mysql-login-path-decrypt-error
             :message (format nil "AES decryption failed: ~A" e)))))

(defun parse-decrypted-sections (decrypted-data)
  "Parse the decrypted data into login path sections"
  (let ((login-paths '())
        (pos 0))

    (loop while (< pos (- (length decrypted-data) 4))
          do (let ((section-length (read-uint32-le decrypted-data pos)))
               (when (and section-length
                         (> section-length 0)
                         (< section-length 10000)  ; Sanity check
                         (<= (+ pos 4 section-length) (length decrypted-data)))
                 (incf pos 4)
                 (let ((section-end (+ pos section-length))
                       (section-data '()))

                   ;; Read key-value pairs in this section
                   (loop while (< pos section-end)
                         do (multiple-value-bind (key next-pos)
                                (read-null-terminated-string decrypted-data pos)
                              (when (and key next-pos (< next-pos section-end))
                                (setf pos next-pos)
                                (multiple-value-bind (value next-pos2)
                                    (read-null-terminated-string decrypted-data pos)
                                  (when (and value next-pos2)
                                    (push (cons key value) section-data)
                                    (setf pos next-pos2))))
                              (unless (and key next-pos (> next-pos pos))
                                (return))))

                   ;; Find the login path name and add to results
                   (when section-data
                     (let ((path-name (cdr (find "path" section-data
                                                :test #'string= :key #'car))))
                       (when (and path-name (> (length path-name) 0))
                         (push (cons path-name
                                    (remove-if (lambda (pair)
                                                (string= (car pair) "path"))
                                              section-data))
                               login-paths))))

                   ;; Move to next section
                   (setf pos section-end)))
               (unless section-length
                 (return))))

    (nreverse login-paths)))

(defun parse-mylogin-cnf (filepath)
  "Parse MySQL .mylogin.cnf file using native AES decryption"
  (handler-case
      (progn
        (unless (probe-file filepath)
          (error 'mysql-login-path-parse-error
                 :message (format nil "File not found: ~A" filepath)))

        (with-open-file (stream filepath :element-type '(unsigned-byte 8))
          (let* ((file-length (file-length stream))
                 (file-data (make-array file-length :element-type '(unsigned-byte 8))))

            ;; Read entire file
            (read-sequence file-data stream)

            (when (< file-length +mysql-total-header-size+)
              (error 'mysql-login-path-parse-error
                     :message "File too small to contain valid MySQL login data"))

            (let* ((aes-key (subseq file-data +mysql-header-size+ +mysql-total-header-size+))
                   (encrypted-data (subseq file-data +mysql-total-header-size+)))

              (when (zerop (length encrypted-data))
                (return-from parse-mylogin-cnf '()))  ; Empty file

              ;; Decrypt and parse
              (let ((decrypted-data (decrypt-mysql-data encrypted-data aes-key)))
                (parse-decrypted-sections decrypted-data))))))

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
