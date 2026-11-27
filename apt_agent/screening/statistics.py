"""Reference-only tail scoring; historical method, not original transductive PyOD."""
import numpy as np

class FeatureReference:
    """Estimate the rarity of event attributes using the training scenes only."""

    def __init__(self, categories, numbers):
        self.n = len(categories)
        self.reference = [np.unique(column, return_counts=True) for column in categories.T]
        train = self.join(categories, numbers)
        self.active = train.std(axis=0, dtype='float64') > 1e-07
        self.mean = train[:, self.active].mean(axis=0, dtype='float64').astype('float32')
        self.scale = train[:, self.active].std(axis=0, dtype='float64').astype('float32')

    def join(self, categories, numbers):
        extra = np.zeros(categories.shape, dtype='float32')
        for column, (keys, counts) in enumerate(self.reference):
            values = categories[:, column]
            positions = np.minimum(np.searchsorted(keys, values), len(keys) - 1)
            hits = np.where(values == keys[positions], counts[positions], 0)
            extra[:, column] = np.where(values != 0, np.log((self.n + 1) / (hits + 1)), 0)
        return np.column_stack((numbers, extra))

    def transform(self, categories, numbers):
        values = (self.join(categories, numbers)[:, self.active] - self.mean) / self.scale
        return np.ascontiguousarray(np.clip(values, -12, 12), dtype='float32')

class FrozenTails:
    """Use the PyOD tail formulas with a training-only ECDF and skew sign."""

    def __init__(self, name):
        self.name = name

    def fit(self, values):
        from scipy.stats import skew
        self.reference = np.sort(values, axis=0).T.copy()
        self.sign = np.sign(skew(values.astype('float64'), axis=0))

    def decision_function(self, values):
        score = np.zeros(len(values))
        for column, reference, sign in zip(values.T, self.reference, self.sign):
            n = len(reference)
            lo = np.searchsorted(reference, column, side='right')
            hi = n - np.searchsorted(reference, column, side='left')
            left = -np.log(np.maximum(lo, 1) / n)
            right = -np.log(np.maximum(hi, 1) / n)
            skewed = left * (sign < 1) + right * (sign > -1)
            symmetric = np.maximum(left, right) if self.name == 'ecod-frozen' else (left + right) / 2
            score += np.maximum(skewed, symmetric)
        return score
