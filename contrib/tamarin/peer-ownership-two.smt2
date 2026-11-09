; Two anchors and two servers. A per-anchor owner slot determines which
; server's claim is anchored; 0 means free. Each step names one anchor and
; one operation on it: claim for alice, claim for bob, release, or observe
; its owner. The watch/release monitor is per anchor, so one anchor's
; releases interleave with another anchor's claims and observations.
; All four checks must return unsat.
(set-logic QF_BV)
(declare-const a1 (_ BitVec 2))
(declare-const a2 (_ BitVec 2))
(declare-const w1 (_ BitVec 2))
(declare-const w2 (_ BitVec 2))
(declare-const r1 Bool)
(declare-const r2 Bool)
(declare-const stutter Bool)
(declare-const anchor (_ BitVec 1))
; 0 claim alice, 1 claim bob, 2 release, 3 observe.
(declare-const kind (_ BitVec 2))
(define-fun none () (_ BitVec 2) #b00)
(define-fun alice () (_ BitVec 2) #b01)
(define-fun bob () (_ BitVec 2) #b10)
(define-fun known ((s (_ BitVec 2))) Bool (bvule s bob))
(define-fun on-one () Bool (= anchor #b0))
(define-fun acting () Bool (not stutter))
(define-fun acting-one () Bool (and acting on-one))
(define-fun acting-two () Bool (and acting (not on-one)))
(define-fun claims () Bool (bvult kind #b10))
(define-fun releases () Bool (= kind #b10))
(define-fun observes () Bool (= kind #b11))
(define-fun target () (_ BitVec 2)
  (ite claims (ite (= kind #b00) alice bob) none))
(define-fun enabled () Bool
  (or stutter
      (and claims (= (ite on-one a1 a2) none))
      (and (not claims) (not (= (ite on-one a1 a2) none)))))
(define-fun next-owner ((slot (_ BitVec 2))) (_ BitVec 2)
  (ite (and acting-one (= slot a1))
    (ite claims target (ite releases none slot))
    (ite (and acting-two (= slot a2))
      (ite claims target (ite releases none slot))
      slot)))
(define-fun next-watched ((slot (_ BitVec 2)) (watch (_ BitVec 2))) (_ BitVec 2)
  (ite (and acting-one (= slot a1) observes) a1
    (ite (and acting-two (= slot a2) observes) a2 watch)))
(define-fun next-released ((slot (_ BitVec 2)) (watch (_ BitVec 2)) (released Bool)) Bool
  (ite (and acting-one (= slot a1) releases (= a1 watch)) true
    (ite (and acting-two (= slot a2) releases (= a2 watch)) true released)))
(define-fun holds ((o1 (_ BitVec 2)) (o2 (_ BitVec 2))
                   (p1 (_ BitVec 2)) (p2 (_ BitVec 2))
                   (c1 Bool) (c2 Bool)) Bool
  (and (known o1) (known o2) (known p1) (known p2)
       (=> (and (not (= p1 none)) (not c1)) (= o1 p1))
       (=> (and (not (= p2 none)) (not c2)) (= o2 p2))))

(echo "initial state")
(push)
(assert (not (holds none none none none false false)))
(check-sat)
(pop)

(echo "anchor one induction")
(push)
(assert (and (holds a1 a2 w1 w2 r1 r2) enabled
             (not (holds (next-owner a1) a2
                         (next-watched a1 w1) w2
                         (next-released a1 w1 r1) r2))))
(check-sat)
(pop)

(echo "anchor two induction")
(push)
(assert (and (holds a1 a2 w1 w2 r1 r2) enabled
             (not (holds a1 (next-owner a2)
                         w1 (next-watched a2 w2)
                         r1 (next-released a2 w2 r2)))))
(check-sat)
(pop)

; Observing a different owner of one anchor requires that owner's release
; since it was first observed, whatever happened to the other anchor.
(echo "change requires release")
(push)
(assert (and (holds a1 a2 w1 w2 r1 r2) observes on-one enabled
             (not (= w1 none)) (not (= a1 w1)) (not r1)))
(check-sat)
(pop)
