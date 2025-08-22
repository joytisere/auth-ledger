;; ------------------------------------------------------------
;; Contract: auth-ledger
;; Purpose : DID & verifiable-credential reference registry
;; Chain   : Stacks / Clarity
;; Version : v1.0.0
;; Author  : (you)
;; ------------------------------------------------------------





;; -----------------------
;; Error codes
;; -----------------------
(define-constant ERR-UNAUTHORIZED        u100)
(define-constant ERR-PAUSED              u101)
(define-constant ERR-DID-EXISTS          u110)
(define-constant ERR-DID-MISSING         u111)
(define-constant ERR-NOT-ISSUER          u120)
(define-constant ERR-CRED-MISSING        u130)
(define-constant ERR-ALREADY-REVOKED     u131)

;; -----------------------
;; Admin & pause control
;; -----------------------
(define-data-var owner principal tx-sender)
(define-data-var paused bool false)

;; -----------------------
;; DID registry
;; One DID per principal (key = subject principal)
;; -----------------------
(define-map dids
  ;; key
  principal
  ;; value
  {
    doc-uri: (string-ascii 256),  ;; e.g. HTTPS/IPFS URI of DID document or its resolver endpoint
    created-at: uint,
    updated-at: uint,
    active: bool
  }
)

;; -----------------------
;; Issuer allow-list
;; -----------------------
(define-map issuers
  principal
  { enabled: bool }
)

;; -----------------------
;; Credential references
;; Each credential is an on-chain reference to an off-chain VC.
;; `hash` is typically a digest (e.g., SHA-256) of the VC JSON or selected fields.
;; -----------------------
(define-data-var cred-counter uint u0)

(define-map credentials
  uint
  {
    subject: principal,             ;; holder / subject of the VC
    issuer: principal,             ;; must be allow-listed
    hash: (buff 32),             ;; digest committing to VC contents
    schema: (string-ascii 80),     ;; short identifier for VC schema/type
    uri: (string-ascii 256),    ;; optional pointer to off-chain VC (IPFS/HTTPS); can be empty ""
    issued-at: uint,
    revoked: bool,
    revoke-reason: (optional (string-ascii 120)),
    revoked-at: (optional uint)
  }
)

;; -----------------------
;; Internal helpers
;; -----------------------

(define-private (ensure-owner)
  (if (is-eq tx-sender (var-get owner))
      (ok true)
      (err ERR-UNAUTHORIZED)
  )
)

(define-private (ensure-not-paused)
  (if (var-get paused)
      (err ERR-PAUSED)
      (ok true)
  )
)

(define-read-only (is-issuer (who principal))
  (ok (match (map-get? issuers who)
        issuer-row (get enabled issuer-row)
        false))
)

;; -----------------------
;; Admin functions
;; -----------------------

(define-public (set-owner (new-owner principal))
  (begin
    (try! (ensure-owner))
    (asserts! (is-some (some new-owner)) (err ERR-UNAUTHORIZED))
    (ok (var-set owner new-owner))
  )
)

(define-public (set-paused (flag bool))
  (begin
    (try! (ensure-owner))
    (ok (var-set paused flag))
  )
)

(define-public (add-issuer (who principal))
  (begin
    (try! (ensure-owner))
    (map-set issuers who { enabled: true })
    (print { event: "issuer-added", who: who })
    (ok true)
  )
)

(define-public (remove-issuer (who principal))
  (begin
    (try! (ensure-owner))
    (map-set issuers who { enabled: false })
    (print { event: "issuer-removed", who: who })
    (ok true)
  )
)

;; -----------------------
;; DID functions
;; -----------------------

(define-read-only (get-did (who principal))
  (map-get? dids who)
)

(define-public (register-did (doc-uri (string-ascii 256)))
  (begin
    (try! (ensure-not-paused))
    (let
      (
        (existing (map-get? dids tx-sender))
      )
      (if (is-some existing)
          (let
            (
              (row (unwrap! existing (err ERR-DID-MISSING)))
            )
            (if (get active row)
                (err ERR-DID-EXISTS)
                (begin
                  (map-set dids tx-sender {
                    doc-uri: doc-uri,
                    created-at: (get created-at row),  ;; keep original creation time
                    updated-at: u0,
                    active: true
                  })
                  (print { event: "did-reactivated", subject: tx-sender, uri: doc-uri })
                  (ok true)
                )
            )
          )
          (begin
            (map-set dids tx-sender {
              doc-uri: doc-uri,
              created-at: u0,
              updated-at: u0,
              active: true
            })
            (print { event: "did-registered", subject: tx-sender, uri: doc-uri })
            (ok true)
          )
      )
    )
  )
)

(define-public (update-did (doc-uri (string-ascii 256)))
  (begin
    (try! (ensure-not-paused))
    (match (map-get? dids tx-sender)
      row
        (if (get active row)
            (begin
              (map-set dids tx-sender {
                doc-uri: doc-uri,
                created-at: (get created-at row),
                updated-at: u0,
                active: true
              })
              (print { event: "did-updated", subject: tx-sender, uri: doc-uri })
              (ok true)
            )
            (err ERR-DID-MISSING)
        )
      (err ERR-DID-MISSING)
    )
  )
)

(define-public (deactivate-did)
  (begin
    (try! (ensure-not-paused))
    (match (map-get? dids tx-sender)
      row
        (begin
          (map-set dids tx-sender {
            doc-uri: (get doc-uri row),
            created-at: (get created-at row),
            updated-at: u0,
            active: false
          })
          (print { event: "did-deactivated", subject: tx-sender })
          (ok true)
        )
      (err ERR-DID-MISSING)
    )
  )
)

;; -----------------------
;; Credential functions
;; -----------------------

(define-read-only (get-credential (cred-id uint))
  (map-get? credentials cred-id)
)

(define-public (issue-credential
  (subject principal)
  (hash (buff 32))
  (schema (string-ascii 80))
  (uri (string-ascii 256))
)
  (begin
    (try! (ensure-not-paused))
    ;; issuer must be allow-listed
    (if (unwrap! (is-issuer tx-sender) (err ERR-NOT-ISSUER))
        (let
          (
            (new-id (+ u1 (var-get cred-counter)))
          )
          (begin
            (map-set credentials new-id {
              subject: subject,
              issuer: tx-sender,
              hash: hash,
              schema: schema,
              uri: uri,
              issued-at: u0,
              revoked: false,
              revoke-reason: none,
              revoked-at: none
            })
            (var-set cred-counter new-id)
            (print {
              event: "credential-issued",
              id: new-id,
              issuer: tx-sender,
              subject: subject,
              schema: schema
            })
            (ok new-id)
          )
        )
        (err ERR-NOT-ISSUER)
    )
  )
)

(define-public (revoke-credential
  (cred-id uint)
  (reason (string-ascii 120))
)
  (begin
    (try! (ensure-not-paused))
    (match (map-get? credentials cred-id)
      row
        (begin
          ;; Only the original issuer or the subject can revoke
          (if (or (is-eq tx-sender (get issuer row))
                  (is-eq tx-sender (get subject row)))
              (if (get revoked row)
                  (err ERR-ALREADY-REVOKED)
                  (begin
                    (map-set credentials cred-id {
                      subject: (get subject row),
                      issuer: (get issuer row),
                      hash: (get hash row),
                      schema: (get schema row),
                      uri: (get uri row),
                      issued-at: (get issued-at row),
                      revoked: true,
                      revoke-reason: (some reason),
                      revoked-at: (some u0)
                    })
                    (print {
                      event: "credential-revoked",
                      id: cred-id,
                      by: tx-sender,
                      reason: reason
                    })
                    (ok true)
                  )
              )
              (err ERR-UNAUTHORIZED)
          )
        )
      (err ERR-CRED-MISSING)
    )
  )
)

;; -----------------------
;; Convenience getters
;; -----------------------

(define-read-only (is-paused) (ok (var-get paused)))

(define-read-only (get-owner) (ok (var-get owner)))

(define-read-only (next-credential-id) (ok (+ u1 (var-get cred-counter))))
