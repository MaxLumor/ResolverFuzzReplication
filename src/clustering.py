

from __future__ import annotations

import numpy as np
from sklearn.cluster import BisectingKMeans


def sse_for_k(vectors: np.ndarray, k: int, random_state: int = 0) -> float:
    if k >= len(vectors):
        return 0.0
    model = BisectingKMeans(n_clusters=k, random_state=random_state, n_init=3)
    model.fit(vectors)
    return float(model.inertia_)  # sum of squared error


def elbow_sse_curve(vectors: np.ndarray, k_range: range) -> dict[int, float]:
    """Replicates Figure 3: SSE vs k for bisecting K-means."""
    return {k: sse_for_k(vectors, k) for k in k_range if k < len(vectors)}


def choose_k_by_elbow(sse_curve: dict[int, float]) -> int:

    ks = sorted(sse_curve.keys())
    if len(ks) < 3:
        return ks[0] if ks else 1
    sse = [sse_curve[k] for k in ks]
    # first differences
    deltas = [sse[i] - sse[i + 1] for i in range(len(sse) - 1)]
    # second differences (how much the drop-off itself is decelerating)
    second_deltas = [deltas[i] - deltas[i + 1] for i in range(len(deltas) - 1)]
    best_idx = int(np.argmax(second_deltas)) + 1  # +1 to align back to ks index
    return ks[best_idx]


def cluster_vectors(vectors: np.ndarray, k: int, random_state: int = 0) -> np.ndarray:
    model = BisectingKMeans(n_clusters=k, random_state=random_state, n_init=3)
    labels = model.fit_predict(vectors)
    return labels
