(defpackage #:mysql-login-path-parser.tests
  (:use #:cl #:fiveam #:mysql-login-path-parser)
  (:export #:run-all-tests))

(in-package #:mysql-login-path-parser.tests)

(def-suite mysql-login-path-parser-tests
  :description "Test suite for MySQL login path parser")

(in-suite mysql-login-path-parser-tests)

(test test-constants
  "Test that constants are defined correctly"
  (is (= mysql-login-path-parser::+mysql-header-size+ 4))
  (is (= mysql-login-path-parser::+mysql-key-size+ 20))
  (is (= mysql-login-path-parser::+mysql-total-header-size+ 24)))

(test test-read-uint32-le
  "Test little-endian integer reading"
  (let ((data #(#x12 #x34 #x56 #x78)))
    (is (= (mysql-login-path-parser::read-uint32-le data 0) #x78563412))))

(test test-read-null-terminated-string
  "Test null-terminated string reading"
  (let ((data (map 'vector #'char-code "hello\x00world")))
    (multiple-value-bind (str next-pos)
        (mysql-login-path-parser::read-null-terminated-string data 0)
      (is (string= str "hello"))
      (is (= next-pos 6)))))

(test test-list-login-paths-nonexistent
  "Test listing paths from nonexistent file"
  (let ((paths (list-login-paths "/nonexistent/file")))
    (is (null paths))))

(test test-get-credentials-nonexistent
  "Test getting credentials from nonexistent file"
  (let ((creds (get-login-path-credentials "test" "/nonexistent/file")))
    (is (null creds))))

(test test-conditions
  "Test that custom conditions are defined"
  (signals mysql-login-path-error
    (error 'mysql-login-path-error :message "test"))
  (signals mysql-login-path-parse-error
    (error 'mysql-login-path-parse-error :message "test"))
  (signals mysql-login-path-decrypt-error
    (error 'mysql-login-path-decrypt-error :message "test")))

(defun run-all-tests ()
  "Run all tests and return T if all pass, NIL otherwise"
  (format t "Running MySQL login path parser tests...~%")
  (let ((results (run 'mysql-login-path-parser-tests)))
    (let ((total-tests (length results))
          (failed-tests (count-if-not (lambda (result)
                                       (typep result 'test-passed))
                                     results)))
      (format t "~%Test Results:~%")
      (format t "  Total tests: ~A~%" total-tests)
      (format t "  Passed: ~A~%" (- total-tests failed-tests))
      (format t "  Failed: ~A~%" failed-tests)
      (if (zerop failed-tests)
          (format t "~%All tests PASSED!~%")
          (format t "~%Some tests FAILED!~%"))
      (zerop failed-tests))))
