; Replacement order, matching EntryVersion::replaces: a stored entry is
; replaced when the incoming entry has a different hash and an order that is
; not lower. The high 64 bits are the u64 iat; the low 64 bits are an
; order-preserving rank for the encoded entry, used only to distinguish
; same-iat versions. Deriving that rank is outside this model.
; All queries must return unsat.
(set-logic QF_BV)
(declare-const a (_ BitVec 128))
(declare-const b (_ BitVec 128))
(declare-const c (_ BitVec 128))
(define-fun iat ((v (_ BitVec 128))) (_ BitVec 64) ((_ extract 127 64) v))
(define-fun rank ((v (_ BitVec 128))) (_ BitVec 64) ((_ extract 63 0) v))
(define-fun differs ((old (_ BitVec 128)) (new (_ BitVec 128))) Bool
  (or (not (= (iat old) (iat new))) (not (= (rank old) (rank new)))))
; Same-iat versions replace each other, so the stored entry can change; a
; lower iat never does.
(define-fun keep ((old (_ BitVec 128)) (new (_ BitVec 128))) (_ BitVec 128)
  (ite (bvugt (iat old) (iat new)) old new))

(echo "a lower iat never replaces")
(push)
(assert (bvult (iat a) (iat b)))
(assert (= (keep b a) a))
(check-sat)
(pop)

(echo "stored iat never decreases")
(push)
(assert (bvult (iat (keep a b)) (iat a)))
(check-sat)
(pop)

; A same-iat version does replace the stored entry, so the stored entry is not
; stable; only its iat is. This query expects sat.
(echo "equal iat replaces the stored entry")
(push)
(assert (and (differs a b) (= (iat a) (iat b)) (not (= (keep a b) a))))
(check-sat)
(pop)

; With distinct iats the winner is the highest iat, so delivery order does not
; matter. Distinctness is required: same-iat versions pick whichever arrived
; last, so two replicas can legitimately differ there.
(echo "distinct iats converge in either order")
(push)
(assert (and (distinct (iat a) (iat b) (iat c))
             (not (= (keep (keep a b) c) (keep (keep a c) b)))))
(check-sat)
(pop)

(echo "distinct iats pick the highest")
(push)
(assert (and (distinct (iat a) (iat b) (iat c))
             (not (= (iat (keep (keep a b) c))
                     (ite (bvuge (iat a) (ite (bvuge (iat b) (iat c)) (iat b) (iat c)))
                          (iat a)
                          (ite (bvuge (iat b) (iat c)) (iat b) (iat c)))))))
(check-sat)
(pop)
