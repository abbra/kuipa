; Independent validity-oracle updates for arbitrarily many entry identifiers.
; Each update evaluates the u64 timestamp check and opens, closes, or leaves
; that entry's symbolic interval. IDs, entry availability, delivery ordering
; and correspondence to Tamarin facts are assumed, not modeled.
; All four queries must return unsat.
(set-logic QF_AUFBV)
(define-sort Entry () (_ BitVec 64))
(declare-const i Entry)
(declare-const j Entry)
(declare-const now (_ BitVec 64))
(declare-const issued (Array Entry (_ BitVec 64)))
(declare-const expires (Array Entry (_ BitVec 64)))
(declare-const oracle (Array Entry Bool))
(define-fun sat-add ((x (_ BitVec 64)) (y (_ BitVec 64))) (_ BitVec 64)
  (ite (bvult (bvadd x y) x) #xffffffffffffffff (bvadd x y)))
(define-fun valid ((entry Entry)) Bool
  (and (bvule now (sat-add (select expires entry) (_ bv300 64)))
       (bvule (select issued entry) (sat-add now (_ bv300 64)))))
(define-fun start-needed ((state (Array Entry Bool)) (entry Entry)) Bool
  (and (not (select state entry)) (valid entry)))
(define-fun end-needed ((state (Array Entry Bool)) (entry Entry)) Bool
  (and (select state entry) (not (valid entry))))
(define-fun update ((state (Array Entry Bool)) (entry Entry)) (Array Entry Bool)
  (store state entry
    (or (and (select state entry) (not (end-needed state entry)))
        (start-needed state entry))))

(echo "updated entry matches concrete validity")
(push)
(assert (not (= (select (update oracle i) i) (valid i))))
(check-sat)
(pop)

(echo "other entries are unchanged")
(push)
(assert (and (not (= i j))
             (not (= (select (update oracle i) j) (select oracle j)))))
(check-sat)
(pop)

(echo "updates commute")
(push)
(assert (not (= (update (update oracle i) j) (update (update oracle j) i))))
(check-sat)
(pop)

(echo "update is idempotent")
(push)
(assert (not (= (update (update oracle i) i) (update oracle i))))
(check-sat)
(pop)
