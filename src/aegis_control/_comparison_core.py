"""Private reason policy on validated facts; no public snapshot/type validation."""
from dataclasses import dataclass


@dataclass(frozen=True)
class EndpointFacts:
    observed_at: int
    source: str
    namespace: str
    generation: str | None
    word_bits: int


def shared_reason(previous, current, as_of, max_age, continuous):
    """Trust both wrappers' complete validation; None means unavailable endpoint."""
    if current is None:
        return "current_unavailable"
    if previous is None:
        return "previous_unavailable"
    if current.observed_at > as_of:
        return "current_future"
    if previous.observed_at > as_of:
        return "previous_future"
    if as_of - current.observed_at > max_age:
        return "current_stale"
    if as_of - previous.observed_at > max_age:
        return "previous_stale"
    if previous.source != current.source:
        return "source_changed"
    if previous.namespace != current.namespace:
        return "namespace_changed"
    if previous.word_bits != current.word_bits:
        return "width_changed"
    if previous.generation is None or current.generation is None:
        return "generation_unknown"
    if previous.generation != current.generation:
        return "generation_changed"
    if current.observed_at == previous.observed_at:
        return "duplicate_time"
    if current.observed_at < previous.observed_at:
        return "out_of_order"
    if not continuous:
        return "continuity_unconfirmed"
    return None


def reading_reason(*, previous_reason, current_reason, previous_value, current_value, shared):
    """Validated reading scalars only; None reason exclusively marks absent endpoint."""
    if current_reason is None or previous_reason is None:
        return shared
    if current_reason != "observed":
        return "current_" + current_reason
    if previous_reason != "observed":
        return "previous_" + previous_reason
    if shared is not None:
        return shared
    if current_value < previous_value:
        return "counter_decreased"
    return "prerequisites_declared"
