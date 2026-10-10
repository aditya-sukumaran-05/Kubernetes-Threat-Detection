"""Strict session-aware splitting that refuses weak or leaky experiments."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from random import Random
from typing import Sequence


class InsufficientDataError(ValueError):
    """Raised when a scientifically defensible grouped split cannot be made."""


@dataclass(frozen=True)
class GroupSplit:
    train_indices: tuple[int, ...]
    test_indices: tuple[int, ...]
    train_session_ids: tuple[str, ...]
    test_session_ids: tuple[str, ...]
    train_class_counts: dict[str, int]
    test_class_counts: dict[str, int]
    strategy: str = "session_holdout_per_class"


def session_holdout_split(labels: Sequence[str], sessions: Sequence[str], random_seed: int = 42) -> GroupSplit:
    """Make a deterministic whole-session split while requiring both classes.

    Attack sessions may validly contain normal warmup/cooldown windows. A
    complete session is therefore kept together, rather than required to be
    class-homogeneous. Both train and held-out test partitions must contain
    normal and attack windows.
    """
    if len(labels) != len(sessions) or not labels:
        raise InsufficientDataError("labels and sessions must be non-empty and have equal length")
    class_by_session: dict[str, set[str]] = defaultdict(set)
    for label, session in zip(labels, sessions):
        if label not in {"normal", "attack"}:
            raise InsufficientDataError("only normal and attack labels can be split")
        class_by_session[session].add(label)
    present = {label for values in class_by_session.values() for label in values}
    missing = [label for label in ("normal", "attack") if label not in present]
    if missing:
        raise InsufficientDataError(f"supervised evaluation requires both classes; missing {missing}")
    ordered_sessions = sorted(class_by_session)
    Random(random_seed).shuffle(ordered_sessions)
    test_sessions: set[str] | None = None
    required = {"normal", "attack"}
    for subset_size in range(1, len(ordered_sessions)):
        for candidate in combinations(ordered_sessions, subset_size):
            candidate_set = set(candidate)
            test_labels = {label for session in candidate_set for label in class_by_session[session]}
            train_labels = {label for session in set(ordered_sessions) - candidate_set for label in class_by_session[session]}
            if test_labels == required and train_labels == required:
                test_sessions = candidate_set
                break
        if test_sessions is not None:
            break
    if test_sessions is None:
        available = {session: sorted(values) for session, values in sorted(class_by_session.items())}
        raise InsufficientDataError(f"need independent sessions that provide both classes in train and test; available={available}")
    test_indices = tuple(index for index, session in enumerate(sessions) if session in test_sessions)
    train_indices = tuple(index for index, session in enumerate(sessions) if session not in test_sessions)
    train_counts = {label: sum(value == label for index, value in enumerate(labels) if index in train_indices) for label in required}
    test_counts = {label: sum(value == label for index, value in enumerate(labels) if index in test_indices) for label in required}
    return GroupSplit(train_indices, test_indices, tuple(sorted(set(sessions) - test_sessions)), tuple(sorted(test_sessions)), train_counts, test_counts)


@dataclass(frozen=True)
class SessionFold:
    held_out_session: str
    train_indices: tuple[int, ...]
    test_indices: tuple[int, ...]
    train_session_ids: tuple[str, ...]
    test_session_ids: tuple[str, ...]
    train_class_counts: dict[str, int]
    test_class_counts: dict[str, int]
    is_valid: bool
    invalid_reason: str | None = None
    strategy: str = "leave_one_session_out"


def leave_one_session_out_splits(
    labels: Sequence[str],
    sessions: Sequence[str],
) -> list[SessionFold]:
    """Generate leave-one-session-out cross-validation folds.

    Each distinct session is held out once for testing while all other sessions
    serve as training data. Folds where training data does not contain both
    classes ('normal' and 'attack') are recorded with is_valid=False and an
    explicit invalid_reason rather than fabricating data or modifying splits.
    """
    if len(labels) != len(sessions) or not labels:
        raise InsufficientDataError("labels and sessions must be non-empty and have equal length")
    for label in labels:
        if label not in {"normal", "attack"}:
            raise InsufficientDataError("only normal and attack labels can be split")

    unique_sessions = sorted(dict.fromkeys(sessions))
    required_classes = {"normal", "attack"}
    folds: list[SessionFold] = []

    for held_out in unique_sessions:
        test_indices = tuple(index for index, session in enumerate(sessions) if session == held_out)
        train_indices = tuple(index for index, session in enumerate(sessions) if session != held_out)
        train_sessions = tuple(s for s in unique_sessions if s != held_out)
        test_sessions = (held_out,)

        train_counts = {label: sum(labels[i] == label for i in train_indices) for label in required_classes}
        test_counts = {label: sum(labels[i] == label for i in test_indices) for label in required_classes}

        has_both_in_train = all(train_counts.get(cls, 0) > 0 for cls in required_classes)
        if not has_both_in_train:
            missing = sorted(cls for cls in required_classes if train_counts.get(cls, 0) == 0)
            folds.append(
                SessionFold(
                    held_out_session=held_out,
                    train_indices=train_indices,
                    test_indices=test_indices,
                    train_session_ids=train_sessions,
                    test_session_ids=test_sessions,
                    train_class_counts=train_counts,
                    test_class_counts=test_counts,
                    is_valid=False,
                    invalid_reason=f"training partition lacks required classes: missing {missing}",
                )
            )
        else:
            folds.append(
                SessionFold(
                    held_out_session=held_out,
                    train_indices=train_indices,
                    test_indices=test_indices,
                    train_session_ids=train_sessions,
                    test_session_ids=test_sessions,
                    train_class_counts=train_counts,
                    test_class_counts=test_counts,
                    is_valid=True,
                    invalid_reason=None,
                )
            )

    return folds

