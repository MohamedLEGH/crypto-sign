#lang info
(define collection "crypto-sign")
(define deps '("base" "math-lib" "crypto-lib" "secp256k1"))
(define build-deps '("scribble-lib" "racket-doc" "rackunit-lib"))
(define scribblings '(("scribblings/crypto-sign.scrbl" ())))
(define pkg-desc "Digital signatures tools for ecdsa and schnorr")
(define version "0.0.1")
(define pkg-authors '(Mohamed Amine LEGHERABA))
(define license 'MIT)
