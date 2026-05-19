(defsystem #:mysql-login-path-parser
  :description "Native Common Lisp parser for MySQL .mylogin.cnf files"
  :author "Matthew Kennedy <burnsidemk@gmail.com>"
  :license "MIT"
  :version "1.0.0"
  :depends-on (#:ironclad #:split-sequence #:alexandria)
  :serial t
  :components ((:file "package")
	       (:file "parser"))
  :in-order-to ((test-op (test-op #:mysql-login-path-parser/tests))))

(defsystem #:mysql-login-path-parser/tests
  :depends-on (#:mysql-login-path-parser #:fiveam)
  :serial t
  :components ((:file "tests"))
  :perform (test-op (o c) (symbol-call :mysql-login-path-parser.tests :run-mysql-tests)))
