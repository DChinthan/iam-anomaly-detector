"""
TensorFlow/Keras Dense Autoencoder for IAM behavioral anomaly detection.

Trained exclusively on normal user behavior. At inference time, high
reconstruction error signals a deviation from learned normal patterns —
no labeled attack data required.

Architecture:
  Encoder: 12 → 8 → 4  (latent space)
  Decoder: 4  → 8 → 12 (reconstruction)
"""

import numpy as np
import pickle
from pathlib import Path

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, callbacks
from sklearn.preprocessing import StandardScaler

from features.extractor import FEATURE_COLS

MODEL_PATH = Path("models/saved/autoencoder.keras")
SCALER_PATH = Path("models/saved/ae_scaler.pkl")


class IAMAutoencoder:
    """Autoencoder that learns the reconstruction manifold of normal IAM sessions."""

    def __init__(self, latent_dim: int = 4, epochs: int = 80):
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.scaler = StandardScaler()
        self.model: keras.Model | None = None
        self._threshold: float = 0.0

    def _build_model(self, input_dim: int) -> keras.Model:
        inp = keras.Input(shape=(input_dim,), name="input")
        x = layers.Dense(8, activation="relu", name="enc_1")(inp)
        x = layers.Dense(self.latent_dim, activation="relu", name="latent")(x)
        x = layers.Dense(8, activation="relu", name="dec_1")(x)
        out = layers.Dense(input_dim, activation="linear", name="reconstruction")(x)
        model = keras.Model(inp, out, name="iam_autoencoder")
        model.compile(optimizer="adam", loss="mse")
        return model

    def fit(self, X_normal: np.ndarray) -> "IAMAutoencoder":
        X_scaled = self.scaler.fit_transform(X_normal)
        self.model = self._build_model(X_scaled.shape[1])
        early_stop = callbacks.EarlyStopping(
            monitor="val_loss", patience=10, restore_best_weights=True
        )
        self.model.fit(
            X_scaled, X_scaled,
            epochs=self.epochs,
            batch_size=16,
            validation_split=0.15,
            callbacks=[early_stop],
            verbose=0,
        )
        train_errors = self._reconstruction_errors(X_scaled)
        self._threshold = float(np.percentile(train_errors, 95))
        return self

    def _reconstruction_errors(self, X_scaled: np.ndarray) -> np.ndarray:
        reconstructed = self.model.predict(X_scaled, verbose=0)
        return np.mean((X_scaled - reconstructed) ** 2, axis=1)

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Returns per-sample scores normalized to [0, 1]."""
        X_scaled = self.scaler.transform(X)
        errors = self._reconstruction_errors(X_scaled)
        lo, hi = errors.min(), errors.max()
        return (errors - lo) / (hi - lo + 1e-9)

    def save(self):
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.model.save(MODEL_PATH)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump((self.scaler, self._threshold), f)
        print(f"Autoencoder saved -> {MODEL_PATH}")

    @classmethod
    def load(cls) -> "IAMAutoencoder":
        instance = cls()
        instance.model = keras.models.load_model(MODEL_PATH)
        with open(SCALER_PATH, "rb") as f:
            instance.scaler, instance._threshold = pickle.load(f)
        return instance
