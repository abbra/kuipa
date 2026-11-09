; Multi-entry retention: two chains joined by one cross edge. Claims and vouches
; are bitmaps; bit j means the entry at index j is present. A vouch at index j
; covers the claim at index j + 1 and survives while the claim at index j names
; it. `cross` enables two edges: chain B's vouch at index 0 also covers chain
; A's claim at index 0, and chain A's vouch at index 0 also covers chain B's
; claim at index 0. Neither of those claims has an in-chain vouch, so each
; survives only because the other chain supports it.
; Membership, validity and signature checks pass; no grace; nothing is added.
; Stages follow AnchorState::retain order (crates/kuipa-enroll/src/anchors.rs):
; drop invalid entries, filter vouches against the surviving claims, drop claims
; no surviving vouch covers, then drop keys no surviving entry references. That
; last stage is a separate filter over keys and is not modelled here.
;
; Check 1 (unsat): without the cross edge, chain A's claim at index 0 is gone by
; pass 2 - the cascade drains one claim per pass.
; Check 2 (sat): with the cross edge it is present at pass 6.
; Check 3 (unsat): with the cross edge both chains stop changing, so the reached
; state is a joint fixed point, not a fully pruned one.
; Check 4 (unsat): that fixed point is claims 0 and 1 with vouch 0 in both
; chains.
; Whether one chain drains therefore depends on another chain's entries; no
; per-entry or per-chain argument composes into a multi-entry bound. Both chains
; must be advanced at every pass - evolving one chain against a constant other
; chain shows nothing about their interaction. Expect unsat, sat, unsat, unsat.
(set-logic QF_BV)
(declare-const cross Bool)
(declare-const claim-a0 (_ BitVec 4))
(declare-const vouch-a0 (_ BitVec 4))
(declare-const claim-b0 (_ BitVec 4))
(declare-const vouch-b0 (_ BitVec 4))

(define-fun vouch-next ((v (_ BitVec 4)) (c (_ BitVec 4))) (_ BitVec 4)
  (bvand v c))
(define-fun covers ((_cv (_ BitVec 4))) (_ BitVec 4)
  (bvshl _cv (_ bv1 4)))
; A claim at index 0 is additionally covered by the other chain's surviving
; vouch at index 0 when the cross edge is enabled.
(define-fun claims-next ((c (_ BitVec 4)) (vnext (_ BitVec 4)) (other (_ BitVec 4))) (_ BitVec 4)
  (bvand c (bvor (covers vnext)
                 (ite (and cross (= (bvand other (_ bv1 4)) (_ bv1 4)))
                      (_ bv1 4) (_ bv0 4)))))

(assert (= claim-a0 (_ bv15 4)))   ; chain A claims 0..3
(assert (= vouch-a0 (_ bv1 4)))    ; chain A vouch 0, covering claim 1 only
(assert (= claim-b0 (_ bv3 4)))    ; chain B claims 0..1
(assert (= vouch-b0 (_ bv1 4)))    ; chain B vouch 0, covering claim 1 only

; Both chains advanced at every pass, in stage order: vouches filtered against
; the claims still present at the start of the pass, then claims filtered
; against those surviving vouches plus the cross edge.
(define-fun va1 () (_ BitVec 4) (vouch-next vouch-a0 claim-a0))
(define-fun vb1 () (_ BitVec 4) (vouch-next vouch-b0 claim-b0))
(define-fun ca1 () (_ BitVec 4) (claims-next claim-a0 va1 vb1))
(define-fun cb1 () (_ BitVec 4) (claims-next claim-b0 vb1 va1))
(define-fun va2 () (_ BitVec 4) (vouch-next va1 ca1))
(define-fun vb2 () (_ BitVec 4) (vouch-next vb1 cb1))
(define-fun ca2 () (_ BitVec 4) (claims-next ca1 va2 vb2))
(define-fun cb2 () (_ BitVec 4) (claims-next cb1 vb2 va2))
(define-fun va3 () (_ BitVec 4) (vouch-next va2 ca2))
(define-fun vb3 () (_ BitVec 4) (vouch-next vb2 cb2))
(define-fun ca3 () (_ BitVec 4) (claims-next ca2 va3 vb3))
(define-fun cb3 () (_ BitVec 4) (claims-next cb2 vb3 va3))
(define-fun va4 () (_ BitVec 4) (vouch-next va3 ca3))
(define-fun vb4 () (_ BitVec 4) (vouch-next vb3 cb3))
(define-fun ca4 () (_ BitVec 4) (claims-next ca3 va4 vb4))
(define-fun cb4 () (_ BitVec 4) (claims-next cb3 vb4 va4))
(define-fun va5 () (_ BitVec 4) (vouch-next va4 ca4))
(define-fun vb5 () (_ BitVec 4) (vouch-next vb4 cb4))
(define-fun ca5 () (_ BitVec 4) (claims-next ca4 va5 vb5))
(define-fun cb5 () (_ BitVec 4) (claims-next cb4 vb5 va5))
(define-fun va6 () (_ BitVec 4) (vouch-next va5 ca5))
(define-fun vb6 () (_ BitVec 4) (vouch-next vb5 cb5))
(define-fun ca6 () (_ BitVec 4) (claims-next ca5 va6 vb6))
(define-fun cb6 () (_ BitVec 4) (claims-next cb5 vb6 va6))

(echo "without the cross edge chain A claim 0 is gone by pass 2")
(push)
(assert (not cross))
(assert (= (bvand ca2 (_ bv1 4)) (_ bv1 4)))
(check-sat)
(pop)

(echo "with the cross edge chain A claim 0 is still present at pass 6")
(push)
(assert cross)
(assert (= (bvand ca6 (_ bv1 4)) (_ bv1 4)))
(check-sat)
(pop)

(echo "with the cross edge neither chain changes after pass 6")
(push)
(assert cross)
(assert (or (not (= ca6 (claims-next ca6 (vouch-next va6 ca6) (vouch-next vb6 cb6))))
            (not (= cb6 (claims-next cb6 (vouch-next vb6 cb6) (vouch-next va6 ca6))))))
(check-sat)
(pop)

(echo "the joint fixed point is claims 0 and 1 with vouch 0 in both chains")
(push)
(assert cross)
(assert (or (not (= ca6 (_ bv3 4))) (not (= va6 (_ bv1 4)))
            (not (= cb6 (_ bv3 4))) (not (= vb6 (_ bv1 4)))))
(check-sat)
(pop)
