; A chain of n claims: claim i names anchor i, whose vouch covers claim i+1.
; All entries initially pass membership and validity, have no grace, and no
; entries are added or replaced. Coverage and signature checks are abstracted.
; Claim 0 has no covering vouch. Stages follow AnchorState::retain: vouches are
; filtered against claims before uncovered claims and unreferenced keys.
; The four inductive checks are unsat; the delayed-pruning witness is sat.
(set-logic QF_LIA)
(declare-const n Int)
(declare-const i Int)
(declare-const t Int)
(define-fun claim ((j Int) (pass Int)) Bool (>= j pass))
(define-fun vouch ((j Int) (pass Int)) Bool (>= (+ j 1) pass))
(define-fun key ((j Int) (pass Int)) Bool (vouch j pass))
(define-fun next-vouch ((j Int)) Bool (and (vouch j t) (claim j t)))
(define-fun next-claim ((j Int)) Bool
  (and (claim j t) (> j 0) (next-vouch (- j 1))))
(define-fun next-key ((j Int)) Bool
  (and (key j t) (or (next-claim j) (next-vouch j))))
(define-fun domain () Bool (and (> n 0) (>= i 0) (< i n) (>= t 0)))

(echo "initial state")
(push)
(assert (and domain (or (not (claim i 0)) (not (vouch i 0)) (not (key i 0)))))
(check-sat)
(pop)

(echo "vouch induction")
(push)
(assert (and domain (not (= (next-vouch i) (vouch i (+ t 1))))))
(check-sat)
(pop)

(echo "claim induction")
(push)
(assert (and domain (not (= (next-claim i) (claim i (+ t 1))))))
(check-sat)
(pop)

(echo "key induction")
(push)
(assert (and domain (not (= (next-key i) (key i (+ t 1))))))
(check-sat)
(pop)

; A claim and its vouch can survive any chosen number of passes, then vanish
; on consecutive passes. n can be arbitrarily large; this is not a timing bound.
(echo "delayed pruning witness")
(push)
(assert (and domain (= i t) (claim i t) (not (claim i (+ t 1)))
             (vouch i (+ t 1)) (not (vouch i (+ t 2)))))
(check-sat)
(pop)
