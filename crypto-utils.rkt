#lang racket/base
(require crypto
         crypto/libcrypto
         secp256k1)
(crypto-factories (list libcrypto-factory))

(define (generate-random-value)
  (define p
    (for/fold ([result 0]) ([byte (in-bytes (crypto-random-bytes 32))])
      (+ byte (* result 256))))
  ; the random number need to be inferior to N (the order of the curve)
  ; if it's not the case (small probability), recompute a random number
  (if (and (< p N) (> p 0)) p (generate-random-value)))

(define (priv-to-pub pk) ; pk in hexa string format
  (point-to-string (rmul-point G (string->number pk 16))))

(define (sha256-hex value)
  (bytes->hex-string (digest 'sha256 (hex->bytes value))))

(define (ripemd160-hex value)
  (bytes->hex-string (digest 'ripemd160 (hex->bytes value))))

(define (doublesha256 value)
  (sha256-hex (sha256-hex value)))

(define (hash160 value)
  (ripemd160-hex (sha256-hex value)))

(define (tagged-hash tag value)
  (define tag-digest
    (bytes->hex-string (digest 'sha256
                               (string->bytes/utf-8
                                tag)))) ; the tag is a utf-8 string value
  (define preimage (string-append tag-digest tag-digest value))
  (sha256-hex preimage))

(provide generate-random-value
         priv-to-pub
         sha256-hex
         ripemd160-hex
         doublesha256
         hash160
         tagged-hash)
