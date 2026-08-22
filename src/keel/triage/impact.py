from keel.catalog.store import CardStore
from keel.errors import UnknownCard
from keel.models import CardStatus, ImpactClass


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
    if impact in {ImpactClass.NONE, ImpactClass.HARDENING}:
        card.status = CardStatus.WONT_FIX_IMPACT
        card.confidence = min(card.confidence, 0.3)
    else:
        card.status = CardStatus.HYPOTHESIS
        card.confidence = max(card.confidence, 0.7)
    store.upsert(card)
    return card.model_dump()
