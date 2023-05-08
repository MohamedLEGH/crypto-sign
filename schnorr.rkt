#lang racket/base
(require racket/format
         math/number-theory
         secp256k1)
(require "crypto-utils.rkt")

(module+ test (require rackunit rackunit/text-ui))
;; for Schnorr signatures

(define (sign-schnorr pk msg) ; pk and msg should be integers
  (define msg-hex (~r msg #:base 16 #:min-width 64 #:pad-string "0"))
  (define a (generate-random-value)) ; Auxiliary random data
  ; Let P = d'⋅G
  (define Point (rmul-point G pk))
  ; Let d = d' if has-even-y(P), otherwise let d = n - d'
  (define d
    (if (= (modulo (field-element-value (point-y Point)) 2) 0) pk (- N pk)))
  ; Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)
  (define preimage-aux (~r a #:base 16 #:min-width 64 #:pad-string "0"))
  (define tag-hex (tagged-hash "BIP0340/aux" preimage-aux))
  (define tag-val (string->number tag-hex 16))
  (define t (bitwise-xor d tag-val))
  ; Let rand = hashBIP0340/nonce(t || bytes(P) || m)
  (define t-hex (~r t #:base 16 #:min-width 64 #:pad-string "0"))
  (define Px-hex
    (~r (field-element-value (point-x Point))
        #:base 16
        #:min-width 64
        #:pad-string "0"))
  (define preimage-nonce (string-append t-hex Px-hex msg-hex))
  (define rand-val (tagged-hash "BIP0340/nonce" preimage-nonce))
  ; Let k' = int(rand) mod n
  (define k-prime (modulo (string->number rand-val 16) N))
  ; Fail if k' = 0.
  (when (= k-prime 0)
    (error "fail, kprime cannot be zero"))
  ; Let R = k'⋅G.
  (define R (rmul-point G k-prime))
  ; Let k = k' if has-even-y(R), otherwise let k = n - k' .
  (define k
    (if (= (modulo (field-element-value (point-y R)) 2) 0)
        k-prime
        (- N k-prime)))
  ; Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
  (define Rx-hex
    (~r (field-element-value (point-x R))
        #:base 16
        #:min-width 64
        #:pad-string "0"))
  (define preimage-challenge (string-append Rx-hex Px-hex msg-hex))
  (define e-hex (tagged-hash "BIP0340/challenge" preimage-challenge))
  (define e (modulo (string->number e-hex 16) N))
  ; Let sig = bytes(R) || bytes((k + ed) mod n).
  (define k-plus-ed (with-modulus N (mod+ k (* e d))))
  (define k-plus-ed-hex (number->string k-plus-ed 16))
  (define sig (string-append Rx-hex k-plus-ed-hex))
  sig)

(define (lift-x x) ; x is a 256-bit unsigned integer
  ;;    Fail if x ≥ p.
  (when (>= x P)
    (error "the point x cannot be >= P"))
  ;;    Let c = x^3 + 7 mod p.
  (define c (with-modulus P (mod+ (modexpt x 3) 7)))
  ;;    Let y = c^((p+1)/4) mod p.
  (define y (with-modulus P (modexpt c (mod/ (mod+ P 1) 4))))
  ;;    Fail if c ≠ y^2 mod p.
  (when (not (= c (with-modulus P (modexpt y 2))))
    (error "c should equal y^2"))
  ;;    Return the unique point P such that x(P) = x and y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
  (define y-val (if (= (modulo y 2) 0) y (- P y)))
  (point (field-element x P) (field-element y-val P) secp256k1))

(define (verify-schnorr
         sig
         pub
         msg) ; pub is an hexval, msg is an int, sig is an hex string
  ;;    Let P = lift-x(int(pk)); fail if that fails.
  (define Point (lift-x (string->number pub 16)))
  ;;    Let r = int(sig[0:32]); fail if r ≥ p.
  (define r-hex (substring sig 0 64))
  (define r (string->number r-hex 16))
  ;;    Let s = int(sig[32:64]); fail if s ≥ n.
  (define s-hex (substring sig 64))
  (define s (string->number s-hex 16))
  ;;    Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
  (define msg-hex (~r msg #:base 16 #:min-width 64 #:pad-string "0"))
  (define e-hex
    (tagged-hash "BIP0340/challenge" (string-append r-hex pub msg-hex)))
  (define e (modulo (string->number e-hex 16) N))
  ;;    Let R = s⋅G - e⋅P.
  ;;     R = point-add(point-mul(G, s), point-mul(P, n - e))
  (define R (add-point (rmul-point G s) (rmul-point Point (- N e))))
  ;;    Fail if is-infinite(R).
  ;;    Fail if not has-even-y(R).
  ;;    Fail if x(R) ≠ r.
  ;(when (equal? R I) (error "R is infinite"))
  ;(when (= (modulo (field-element-value (point-y R)) 2) 1) (error "y(R) is odd"))
  ;(when (not (equal? r-compute r)) (error "x(R) is not equal to r"))
  ;;   Return success iff no failure occurred before reaching this point.
  (define r-compute (field-element-value (point-x R)))
  (cond
    [(equal? R I) #f]
    [(= (modulo (field-element-value (point-y R)) 2) 1) #f]
    [(not (equal? r-compute r)) #f]
    [else #t]))

(define (tweak-pubkey
         pubkey
         h) ;  pub as a x-only public key in hex format, h as a hexstring
  (define Point (lift-x (string->number pubkey 16))) ; works
  (define hashhex (tagged-hash "TapTweak" (string-append pubkey h)))
  (define hashval (string->number hashhex 16)) ; works
  (when (>= hashval N)
    (error "value is superior to the order of the curve"))
  (define Q (add-point Point (rmul-point G hashval))) ; tweak of the public key
  ; convert Q to hex (only the x part)
  (define Qx (point-to-pubschnorr-string Q))
  Qx)

(define (point-to-pubschnorr-string
         pub) ; take a public point and return a hexstring of the x value
  (substring (point-to-string pub) 0 64))

(module+ test (define test-schnorr
  (test-suite
   "Tests for schnorr.rkt"
   (let ()
     (define e4 (generate-random-value)) ; a private key is just a random number
     (define pub4
       (point-to-pubschnorr-string
        (rmul-point G e4))) ; G*e to get the public key
     (define z4 (generate-random-value)) ; just a random message
     (define sig4 (sign-schnorr e4 z4))
     (test-case "# Test case 4: sign and verify Schnorr"
                (check-true (verify-schnorr sig4 pub4 z4)))

     (define e5
       #x0000000000000000000000000000000000000000000000000000000000000003) ; a private key is just a random number
     (define pub5
       "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9") ; G*e to get the public key
     (define z5
       #x0000000000000000000000000000000000000000000000000000000000000000) ; just a random message
     (define sig5-compute (sign-schnorr e5 z5))
     (define sig5
       "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")

     (test-case "# Test case 5: verify Schnorr"
                (check-true (verify-schnorr sig5 pub5 z5))
                (check-true (verify-schnorr sig5-compute pub5 z5)))

     (define e5bis
       #x0000000000000000000000000000000000000000000000000000000000000006) ; a private key is just a random number
     (define pub5bis
       "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556") ; G*e to get the public key
     (define sig5-computebis (sign-schnorr e5bis z5))

     (test-case "# Test case 5bis: verify Schnorr : odd y pubkey"
                (check-true (verify-schnorr sig5-computebis pub5bis z5)))

     (define sig5bis
       "E807831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")

     (test-case "# Test case 5.1: false signature s"
                (check-false (verify-schnorr sig5bis pub5 z5)))

     (define z5bis
       #xEC208BAA0FC1C29F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60)

     (test-case "# Test case 5.2: false message"
                (check-false (verify-schnorr sig5 pub5 z5bis)))

     (define pub53
       (point
        (field-element
         #x887386E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C
         P)
        (field-element
         #x61DE6D95231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34
         P)
        secp256k1))
     (define pub53-val (point-to-pubschnorr-string pub53)) ;

     (test-case "# Test case 5.3: false pub key x"
                (check-false (verify-schnorr sig5 pub53-val z5)))

     (define pub5bisbis
       (point
        (field-element
         #x887387E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C
         P)
        (field-element
         #x61DE6D94231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34
         P)
        secp256k1))
     (define pub5bisbis-val (point-to-pubschnorr-string pub5bisbis)) ;

     (test-case "# Test case 5.4: false pub key y"
                (check-false (verify-schnorr sig5 pub5bisbis-val z5))))))

(run-tests test-schnorr))


(provide sign-schnorr
         lift-x
         verify-schnorr
         tweak-pubkey
         point-to-pubschnorr-string)
