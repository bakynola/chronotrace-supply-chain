;; ChronoTrace - Temporal Supply Chain Verification System

;; ============================================================
;; ERRORS
;; ============================================================

(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-PRODUCT-NOT-FOUND     (err u101))
(define-constant ERR-PRODUCT-EXISTS        (err u102))
(define-constant ERR-TRANSFER-NOT-FOUND    (err u103))
(define-constant ERR-QUALITY-TOO-LOW       (err u104))
(define-constant ERR-PRODUCT-EXPIRED       (err u105))
(define-constant ERR-INVALID-QUALITY       (err u106))
(define-constant ERR-INVALID-TEMP          (err u107))
(define-constant ERR-NOT-CUSTODIAN         (err u108))
(define-constant ERR-TRANSFER-ALREADY-DONE (err u109))

;; ============================================================
;; CONSTANTS
;; ============================================================

;; Quality scores range from 0 (ruined) to 100 (perfect)
(define-constant MAX-QUALITY u100)

;; Decay rate denominator: quality lost per block per degree above threshold
;; e.g. 1 unit per 144 blocks (~1 day on Stacks) at threshold temp
(define-constant DECAY-BLOCKS-PER-UNIT u144)

;; Reputation token reward amounts
(define-constant REWARD-GOOD-CUSTODY   u10)
(define-constant REWARD-TRANSFER       u2)

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Auto-incrementing product ID counter
(define-data-var next-product-id uint u1)

;; Auto-incrementing transfer request ID counter
(define-data-var next-transfer-id uint u1)

;; Core product registry
;; fingerprint: a content hash (bytes32) of off-chain IPFS sensor data
(define-map products
  { product-id: uint }
  {
    manufacturer:          principal,
    custodian:             principal,
    name:                  (string-ascii 64),
    category:              (string-ascii 32),   ;; pharma | food | luxury
    fingerprint:           (buff 32),            ;; IPFS content hash / ZK attestation
    registered-at:         uint,                 ;; block height
    expiry-block:          uint,                 ;; block height at expiry
    quality-score:         uint,                 ;; 0-100
    min-quality-threshold: uint,                 ;; auto-reject transfers below this
    max-temp-celsius:      int,                  ;; signed: max acceptable temp (x10, e.g. 25 = 2.5C)
    last-updated-block:    uint,
    is-active:             bool
  }
)

;; Immutable custody chain log (append-only via sequential IDs)
(define-map custody-events
  { product-id: uint, event-index: uint }
  {
    from-custodian:  principal,
    to-custodian:    principal,
    block-height:    uint,
    quality-at-transfer: uint,
    temperature-log: int,     ;; signed int x10 (e.g. 22 = 2.2C, -5 = -0.5C)
    notes-hash:      (buff 32) ;; IPFS hash of full sensor log
  }
)

;; Tracks how many custody events each product has had
(define-map product-event-count
  { product-id: uint }
  { count: uint }
)

;; Pending transfer requests (initiator proposes, recipient accepts)
(define-map transfer-requests
  { transfer-id: uint }
  {
    product-id:   uint,
    from:         principal,
    to:           principal,
    proposed-at:  uint,
    temperature-log: int,
    notes-hash:   (buff 32),
    status:       (string-ascii 16)  ;; pending | accepted | rejected | expired
  }
)

;; Stakeholder reputation / governance token balances
(define-map reputation-balances
  { owner: principal }
  { balance: uint }
)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

;; Apply temporal decay to quality based on blocks elapsed and temperature.
;; Simple linear model: each DECAY-BLOCKS-PER-UNIT blocks reduces quality by 1.
;; Temperature multiplier: if recorded temp > max allowed, decay doubles.
(define-private (compute-current-quality
    (current-quality uint)
    (last-updated-block uint)
    (max-temp int)
    (recorded-temp int))
  (let (
    (blocks-elapsed (- block-height last-updated-block))
    (base-decay     (/ blocks-elapsed DECAY-BLOCKS-PER-UNIT))
    ;; Double decay when temperature exceeds max threshold
    (temp-penalty   (if (> recorded-temp max-temp) base-decay u0))
    (total-decay    (+ base-decay temp-penalty))
  )
    (if (>= total-decay current-quality)
      u0
      (- current-quality total-decay)
    )
  )
)

;; Mint reputation tokens for a principal
(define-private (reward-reputation (recipient principal) (amount uint))
  (let (
    (current-balance (default-to u0
      (get balance (map-get? reputation-balances { owner: recipient }))))
  )
    (map-set reputation-balances
      { owner: recipient }
      { balance: (+ current-balance amount) }
    )
  )
)

;; ============================================================
;; PUBLIC FUNCTIONS
;; ============================================================

;; Register a new product on-chain.
;; Only the tx-sender becomes the manufacturer and initial custodian.
(define-public (register-product
    (name (string-ascii 64))
    (category (string-ascii 32))
    (fingerprint (buff 32))
    (shelf-life-blocks uint)
    (min-quality-threshold uint)
    (max-temp-celsius int))
  (let (
    (product-id (var-get next-product-id))
  )
    (asserts! (<= min-quality-threshold MAX-QUALITY) ERR-INVALID-QUALITY)
    (asserts! (is-none (map-get? products { product-id: product-id })) ERR-PRODUCT-EXISTS)
    (map-set products
      { product-id: product-id }
      {
        manufacturer:          tx-sender,
        custodian:             tx-sender,
        name:                  name,
        category:              category,
        fingerprint:           fingerprint,
        registered-at:         block-height,
        expiry-block:          (+ block-height shelf-life-blocks),
        quality-score:         MAX-QUALITY,
        min-quality-threshold: min-quality-threshold,
        max-temp-celsius:      max-temp-celsius,
        last-updated-block:    block-height,
        is-active:             true
      }
    )
    (map-set product-event-count { product-id: product-id } { count: u0 })
    (var-set next-product-id (+ product-id u1))
    (ok product-id)
  )
)

;; Update a product's fingerprint (e.g. new IPFS sensor batch uploaded).
;; Only the current custodian may call this.
;; Also applies temporal decay and logs the temperature reading.
(define-public (update-sensor-data
    (product-id uint)
    (new-fingerprint (buff 32))
    (temperature-log int))
  (let (
    (product (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
  )
    (asserts! (is-eq tx-sender (get custodian product))  ERR-NOT-CUSTODIAN)
    (asserts! (get is-active product)                    ERR-PRODUCT-EXPIRED)
    (asserts! (< block-height (get expiry-block product)) ERR-PRODUCT-EXPIRED)
    (let (
      (new-quality (compute-current-quality
        (get quality-score product)
        (get last-updated-block product)
        (get max-temp-celsius product)
        temperature-log))
    )
      (map-set products
        { product-id: product-id }
        (merge product {
          fingerprint:        new-fingerprint,
          quality-score:      new-quality,
          last-updated-block: block-height
        })
      )
      ;; Reward custodian for keeping quality above threshold
      (if (>= new-quality (get min-quality-threshold product))
        (reward-reputation tx-sender REWARD-GOOD-CUSTODY)
        false
      )
      (ok new-quality)
    )
  )
)

;; Initiate a custody transfer request.
;; The current custodian proposes handing off to a new custodian.
(define-public (propose-transfer
    (product-id uint)
    (recipient principal)
    (temperature-log int)
    (notes-hash (buff 32)))
  (let (
    (product     (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
    (transfer-id (var-get next-transfer-id))
    (cur-quality (compute-current-quality
      (get quality-score product)
      (get last-updated-block product)
      (get max-temp-celsius product)
      temperature-log))
  )
    (asserts! (is-eq tx-sender (get custodian product)) ERR-NOT-CUSTODIAN)
    (asserts! (get is-active product)                   ERR-PRODUCT-EXPIRED)
    (asserts! (< block-height (get expiry-block product)) ERR-PRODUCT-EXPIRED)
    ;; Smart contract enforces quality gate -- cannot transfer below threshold
    (asserts! (>= cur-quality (get min-quality-threshold product)) ERR-QUALITY-TOO-LOW)
    (map-set transfer-requests
      { transfer-id: transfer-id }
      {
        product-id:      product-id,
        from:            tx-sender,
        to:              recipient,
        proposed-at:     block-height,
        temperature-log: temperature-log,
        notes-hash:      notes-hash,
        status:          "pending"
      }
    )
    (var-set next-transfer-id (+ transfer-id u1))
    (ok transfer-id)
  )
)

;; Accept a pending transfer request.
;; Only the intended recipient may accept.
;; Executes the custody handoff and appends an immutable custody event.
(define-public (accept-transfer (transfer-id uint))
  (let (
    (request (unwrap! (map-get? transfer-requests { transfer-id: transfer-id }) ERR-TRANSFER-NOT-FOUND))
    (product-id (get product-id request))
    (product    (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
    (event-count (default-to u0
      (get count (map-get? product-event-count { product-id: product-id }))))
    (cur-quality (compute-current-quality
      (get quality-score product)
      (get last-updated-block product)
      (get max-temp-celsius product)
      (get temperature-log request)))
  )
    (asserts! (is-eq tx-sender (get to request))                    ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status request) "pending")                ERR-TRANSFER-ALREADY-DONE)
    (asserts! (< block-height (get expiry-block product))           ERR-PRODUCT-EXPIRED)
    (asserts! (>= cur-quality (get min-quality-threshold product))  ERR-QUALITY-TOO-LOW)
    ;; Append immutable custody event
    (map-set custody-events
      { product-id: product-id, event-index: event-count }
      {
        from-custodian:       (get from request),
        to-custodian:         tx-sender,
        block-height:         block-height,
        quality-at-transfer:  cur-quality,
        temperature-log:      (get temperature-log request),
        notes-hash:           (get notes-hash request)
      }
    )
    (map-set product-event-count
      { product-id: product-id }
      { count: (+ event-count u1) }
    )
    ;; Update product custodian and quality
    (map-set products
      { product-id: product-id }
      (merge product {
        custodian:          tx-sender,
        quality-score:      cur-quality,
        last-updated-block: block-height
      })
    )
    ;; Mark transfer as accepted
    (map-set transfer-requests
      { transfer-id: transfer-id }
      (merge request { status: "accepted" })
    )
    ;; Reward both parties for a successful transfer
    (reward-reputation (get from request) REWARD-TRANSFER)
    (reward-reputation tx-sender          REWARD-TRANSFER)
    (ok cur-quality)
  )
)

;; Reject a pending transfer request.
;; Only the intended recipient may reject.
(define-public (reject-transfer (transfer-id uint))
  (let (
    (request (unwrap! (map-get? transfer-requests { transfer-id: transfer-id }) ERR-TRANSFER-NOT-FOUND))
  )
    (asserts! (is-eq tx-sender (get to request))     ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status request) "pending") ERR-TRANSFER-ALREADY-DONE)
    (map-set transfer-requests
      { transfer-id: transfer-id }
      (merge request { status: "rejected" })
    )
    (ok true)
  )
)

;; Mark a product as inactive / recalled by the manufacturer.
(define-public (deactivate-product (product-id uint))
  (let (
    (product (unwrap! (map-get? products { product-id: product-id }) ERR-PRODUCT-NOT-FOUND))
  )
    (asserts! (is-eq tx-sender (get manufacturer product)) ERR-NOT-AUTHORIZED)
    (map-set products
      { product-id: product-id }
      (merge product { is-active: false })
    )
    (ok true)
  )
)

;; ============================================================
;; READ-ONLY FUNCTIONS
;; ============================================================

;; Get full product details including live-computed quality score.
(define-read-only (get-product (product-id uint))
  (match (map-get? products { product-id: product-id })
    product (ok (merge product {
      ;; Compute quality on-the-fly using last recorded temperature (0 placeholder)
      ;; Callers should use get-live-quality for a temperature-adjusted view
      quality-score: (compute-current-quality
        (get quality-score product)
        (get last-updated-block product)
        (get max-temp-celsius product)
        (get max-temp-celsius product)) ;; conservative: assume at threshold
    }))
    ERR-PRODUCT-NOT-FOUND
  )
)

;; Compute the current quality given an observed temperature reading.
;; Useful for predictive routing decisions before committing a transfer.
(define-read-only (get-live-quality
    (product-id uint)
    (temperature-now int))
  (match (map-get? products { product-id: product-id })
    product (ok (compute-current-quality
      (get quality-score product)
      (get last-updated-block product)
      (get max-temp-celsius product)
      temperature-now))
    ERR-PRODUCT-NOT-FOUND
  )
)

;; Get a specific custody event from the immutable provenance chain.
(define-read-only (get-custody-event (product-id uint) (event-index uint))
  (match (map-get? custody-events { product-id: product-id, event-index: event-index })
    event (ok event)
    ERR-TRANSFER-NOT-FOUND
  )
)

;; Get total custody event count for a product.
(define-read-only (get-event-count (product-id uint))
  (ok (default-to u0
    (get count (map-get? product-event-count { product-id: product-id }))))
)

;; Get a pending transfer request.
(define-read-only (get-transfer-request (transfer-id uint))
  (match (map-get? transfer-requests { transfer-id: transfer-id })
    req (ok req)
    ERR-TRANSFER-NOT-FOUND
  )
)

;; Get reputation / governance token balance for a principal.
(define-read-only (get-reputation (owner principal))
  (ok (default-to u0
    (get balance (map-get? reputation-balances { owner: owner }))))
)

;; Check if a product has expired.
(define-read-only (is-expired (product-id uint))
  (match (map-get? products { product-id: product-id })
    product (ok (>= block-height (get expiry-block product)))
    ERR-PRODUCT-NOT-FOUND
  )
)

;; Get the next product ID (useful for off-chain indexing).
(define-read-only (get-next-product-id)
  (ok (var-get next-product-id))
)

;; Get the next transfer ID (useful for off-chain indexing).
(define-read-only (get-next-transfer-id)
  (ok (var-get next-transfer-id))
)
