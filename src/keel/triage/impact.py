from keel.catalog.store import CardStore
from keel.errors import UnknownCard
from keel.models import CardStatus, ImpactClass, ValidationState
from keel.triage.filters import priority_score


def apply_impact(
    store: CardStore,
    card_id: str,
    impact: ImpactClass,
    preconditions: str,
    hunter_why: str,
) -> dict:
    card = store.get(card_id)
    if card is None:
        raise UnknownCard(card_id)
    card.impact_class = impact
    card.preconditions = preconditions
    card.evidence["hunter_why"] = hunter_why
    card.evidence["impact_claim_source"] = "agent_hypothesis"
    proof_state = card.validation_state in {
        ValidationState.PROVEN,
        ValidationState.REFUTED,
    }
    if not proof_state:
        if impact in {ImpactClass.NONE, ImpactClass.HARDENING}:
            card.status = CardStatus.WONT_FIX_IMPACT
            card.confidence = min(card.confidence, 0.3)
        else:
            card.status = CardStatus.HYPOTHESIS
            if card.validation_state == ValidationState.OBSERVED:
                card.validation_state = ValidationState.HYPOTHESIS
    card.priority_score = priority_score(card)
    store.upsert(card)
    return card.model_dump()
