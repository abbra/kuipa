; One anchor, two servers; 0 means no owner, 1 and 2 name the servers.
; An observation starts a watch; a release marks the watch until reobserved.
; All three checks must return unsat.
(set-logic QF_BV)
(declare-const owner (_ BitVec 2))
(declare-const watched (_ BitVec 2))
(declare-const released Bool)
(declare-const operation (_ BitVec 3))
(define-fun none () (_ BitVec 2) #b00)
(define-fun alice () (_ BitVec 2) #b01)
(define-fun bob () (_ BitVec 2) #b10)
(define-fun known ((s (_ BitVec 2))) Bool (bvule s bob))
; Operations: 0 stutter, 1/2 claim a free anchor, 3 release, 4 observe.
(define-fun enabled () Bool
  (or (= operation #b000)
      (and (or (= operation #b001) (= operation #b010)) (= owner none))
      (and (= operation #b011) (not (= owner none)))
      (and (= operation #b100) (not (= owner none)))))
(define-fun next-owner () (_ BitVec 2)
  (ite (= operation #b001) alice
    (ite (= operation #b010) bob
      (ite (= operation #b011) none owner))))
(define-fun next-watched () (_ BitVec 2)
  (ite (= operation #b100) owner watched))
(define-fun next-released () Bool
  (ite (= operation #b100) false
    (or released (and (= operation #b011) (= owner watched)))))
(define-fun invariant ((o (_ BitVec 2)) (w (_ BitVec 2)) (r Bool)) Bool
  (and (known o) (known w) (=> (and (not (= w none)) (not r)) (= o w))))

(echo "initial state")
(push)
(assert (not (invariant none none false)))
(check-sat)
(pop)

(echo "inductive step")
(push)
(assert (and (invariant owner watched released) enabled
             (not (invariant next-owner next-watched next-released))))
(check-sat)
(pop)

; A new observation of a different owner requires a release since the watch.
(echo "change requires release")
(push)
(assert (and (invariant owner watched released) (= operation #b100) enabled
             (not (= watched none)) (not (= owner watched)) (not released)))
(check-sat)
(pop)
