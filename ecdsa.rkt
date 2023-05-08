#lang racket/base
(require racket/format
         math/number-theory
         secp256k1)
(require "crypto-utils.rkt")

(module+ test (require rackunit rackunit/text-ui))

(define (sign-ecdsa pk msg)
  ; pk : int
  ; msg : int
  ; output : hexadecimal string, with concatenation of r and s
  (define k (generate-random-value))
  (define R (rmul-point G k))
  (define r-val (field-element-value (point-x R)))
  (define s-val (with-modulus N (mod/ (+ msg (* r-val pk)) k)))
  (define r-hex (~r r-val #:base 16 #:min-width 64 #:pad-string "0"))
  (define s-hex (~r s-val #:base 16 #:min-width 64 #:pad-string "0"))
  (string-append r-hex s-hex))

(define (verify-ecdsa
         sig
         pubhex
         msg) ; should check if verify signature is the same in bitcoin
  ; sig is an hex string (64 bytes)
  ; pubhex is a public point as an hexadecimal string (concatenation of x and y)
  ; msg is an int
  ; output a boolean
  (define pub (string-to-point pubhex))
  (define r-hex (substring sig 0 64))
  (define s-hex (substring sig 64))
  (define r-val (string->number r-hex 16))
  (define s-val (string->number s-hex 16))
  (define u (with-modulus N (mod/ msg s-val)))
  (define v (with-modulus N (mod/ r-val s-val)))
  (define r-compute
    (field-element-value
     (point-x (add-point (rmul-point G u) (rmul-point pub v)))))
  (equal? r-compute r-val))

(module+ test
(define test-ecdsa
  (test-suite
   "Tests for schnorr.rkt"
   (let ()
     (define pub1
       (point
        (field-element
         #x887387E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C
         P)
        (field-element
         #x61DE6D95231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34
         P)
        secp256k1))
     (define z1
       #xEC208BAA0FC1C19F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60)
     (define r1
       #xAC8D1C87E51D0D441BE8B3DD5B05C8795B48875DFFE00B7FFCFAC23010D3A395)
     (define s1
       #x68342CEFF8935EDEDD102DD876FFD6BA72D6A427A3EDB13D26EB0781CB423C4)
     (define r1-hex (~r r1 #:base 16 #:min-width 64 #:pad-string "0"))
     (define s1-hex (~r s1 #:base 16 #:min-width 64 #:pad-string "0"))
     (define sig1 (string-append r1-hex s1-hex))

     (test-case "Test authenticity for ECDSA signatures"
                (check-true (verify-ecdsa sig1 (point-to-string pub1) z1)))

     (define r1bis
       #xAB8D1C87E51D0D441BE8B3DD5B05C8795B48875DFFE00B7FFCFAC23010D3A395)
     (define r1bis-hex (~r r1bis #:base 16 #:min-width 64 #:pad-string "0"))
     (define sig11 (string-append r1bis-hex s1-hex))

     (test-case "# Test case 1.1: false signature r"
                (check-false (verify-ecdsa sig11 (point-to-string pub1) z1)))

     (define s1bis
       #x68242CEFF8935EDEDD102DD876FFD6BA72D6A427A3EDB13D26EB0781CB423C4)
     (define s1bis-hex (~r s1bis #:base 16 #:min-width 64 #:pad-string "0"))
     (define sig12 (string-append r1-hex s1bis-hex))

     (test-case "# Test case 1.2: false signature s"
                (check-false (verify-ecdsa sig12 (point-to-string pub1) z1)))

     (define z1bis
       #xEC208BAA0FC1C29F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60)

     (test-case "# Test case 1.3: false message"
                (check-false (verify-ecdsa sig1 (point-to-string pub1) z1bis)))

     (define pub1bis
       (point
        (field-element
         #x887386E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C
         P)
        (field-element
         #x61DE6D95231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34
         P)
        secp256k1))

     (test-case "# Test case 1.4: false pub key x"
                (check-false (verify-ecdsa sig1 (point-to-string pub1bis) z1)))

     (define pub1bisbis
       (point
        (field-element
         #x887387E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C
         P)
        (field-element
         #x61DE6D94231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34
         P)
        secp256k1))

     (test-case "# Test case 1.4bis: false pub key y"
                (check-false (verify-ecdsa sig1 (point-to-string pub1bisbis) z1)))

     (define z2
       #x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D)
     (define r2
       #xEFF69EF2B1BD93A66ED5219ADD4FB51E11A840F404876325A1E8FFE0529A2C)
     (define s2
       #xC7207FEE197D27C618AEA621406F6BF5EF6FCA38681D82B2F06FDDBDCE6FEAB6)
     (define r2-hex (~r r2 #:base 16 #:min-width 64 #:pad-string "0"))
     (define s2-hex (~r s2 #:base 16 #:min-width 64 #:pad-string "0"))
     (define sig2 (string-append r2-hex s2-hex))

     (test-case "# Test case 2: different signature and same pubkey"
                (check-true (verify-ecdsa sig2 (point-to-string pub1) z2)))

     (define e3 (generate-random-value)) ; a private key is just a random number
     (define pub3 (rmul-point G e3)) ; G*e to get the public key
     (define z3 (generate-random-value)) ; just a random message
     (define sig3 (sign-ecdsa e3 z3))

     (test-case "# Test case 3: sign and verify"
                (check-true (verify-ecdsa sig3 (point-to-string pub3) z3))))))

(run-tests test-ecdsa))

(provide sign-ecdsa
         verify-ecdsa)
