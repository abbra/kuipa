; Exact u64 validity arithmetic from delegation.rs, with 300 seconds skew.
; Run with an SMT-LIB 2 bitvector solver: six unsat results, then sat.
(set-logic QF_BV)
(declare-const iat (_ BitVec 64))
(declare-const exp (_ BitVec 64))
(declare-const now (_ BitVec 64))
(declare-const later (_ BitVec 64))
(declare-const latest (_ BitVec 64))
(declare-const oracle-open Bool)
(define-fun skew () (_ BitVec 64) (_ bv300 64))
(declare-const max-period (_ BitVec 64))
(define-fun max64 () (_ BitVec 64) #xffffffffffffffff)
(define-fun sat-add ((x (_ BitVec 64)) (y (_ BitVec 64))) (_ BitVec 64)
  (ite (bvult (bvadd x y) x) max64 (bvadd x y)))
(define-fun sat-sub ((x (_ BitVec 64)) (y (_ BitVec 64))) (_ BitVec 64)
  (ite (bvult x y) (_ bv0 64) (bvsub x y)))
(define-fun valid-at ((t (_ BitVec 64))) Bool
  (and (bvule t (sat-add exp skew)) (bvule iat (sat-add t skew))))
(define-fun valid () Bool (valid-at now))

; One-entry simulation scheduler: choose start/end to match the next check.
; The mapping to Tamarin's fresh interval IDs and In(entry) is assumed.
(define-fun start-needed () Bool (and (not oracle-open) (valid-at later)))
(define-fun end-needed () Bool (and oracle-open (not (valid-at later))))
(define-fun next-open () Bool (or (and oracle-open (not end-needed)) start-needed))

(echo "one-step oracle simulation")
(push)
(assert (and (= oracle-open (valid-at now))
             (or (and start-needed oracle-open)
                 (and end-needed (not oracle-open))
                 (not (= next-open (valid-at later))))))
(check-sat)
(pop)

; The implementation accepts exactly the inclusive skew-expanded interval,
; including saturation at both ends of the u64 domain.
(echo "expanded interval")
(push)
(assert (not (= valid
  (and (bvuge now (sat-sub iat skew)) (bvule now (sat-add exp skew))))))
(check-sat)
(pop)

; Valid periods always contain their original inclusive interval.
(echo "original interval")
(push)
(assert (and (bvult iat exp) (bvuge now iat) (bvule now exp) (not valid)))
(check-sat)
(pop)

; A timestamp strictly outside either expanded boundary is never accepted.
(echo "outside boundaries")
(push)
(assert (and valid
  (or (bvult now (sat-sub iat skew)) (bvugt now (sat-add exp skew)))))
(check-sat)
(pop)

; check_period rejects empty or reversed periods and durations over max.
(echo "period duration")
(push)
(assert
  (not
    (= (and (bvugt exp iat) (bvule (bvsub exp iat) max-period))
       (and (bvugt exp iat)
            (bvule (bvsub ((_ zero_extend 1) exp) ((_ zero_extend 1) iat))
                   ((_ zero_extend 1) max-period))))))
(check-sat)
(pop)

; For a fixed entry and nondecreasing clock, validity cannot resume once lost.
(echo "monotonic interval")
(push)
(assert (and (bvule now later) (bvule later latest)
             (valid-at now) (not (valid-at later)) (valid-at latest)))
(check-sat)
(pop)

; A permitted period becomes valid again if the clock moves backwards.
(echo "clock rollback witness")
(push)
(assert (and (bvult iat exp) (bvule (bvsub exp iat) (_ bv34560000 64))
             (valid-at now) (bvult now later) (not (valid-at later))
             (bvult latest later) (valid-at latest)))
(check-sat)
(pop)
