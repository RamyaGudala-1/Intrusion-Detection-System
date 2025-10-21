import os
import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from sklearn.metrics import roc_curve, auc, confusion_matrix

# Paths to your saved evaluation files (adjust if needed)
summary_path = "../logs/KDDTest+_eval_summary.json"
predictions_path = "../logs/KDDTest+_predictions.csv"

# Load evaluation summary and predictions
with open(summary_path, "r") as f:
    summary = json.load(f)

df_preds = pd.read_csv(predictions_path)

# Extract labels and probabilities
true_labels = df_preds["true_label"].astype(str)
predicted_labels = df_preds["predicted_label"].astype(str)
prob_attack = df_preds.get("prob_attack", None)

# Confusion matrix
cm = np.array(summary["confusion_matrix"])
labels = ["Normal", "Attack"]

plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
plt.xlabel("Predicted")
plt.ylabel("True")
plt.title("Confusion Matrix")
plt.tight_layout()
plt.show()

# ROC Curve (if probability scores exist)
if prob_attack is not None:
    y_true_bin = true_labels.apply(lambda x: 0 if x == "normal" else 1).values
    fpr, tpr, _ = roc_curve(y_true_bin, prob_attack)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=1, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# True vs predicted label distribution
class_counts = pd.crosstab(true_labels, predicted_labels)
class_counts.plot(kind="bar", figsize=(6, 4), colormap="Paired")
plt.title("True vs Predicted Class Distribution")
plt.xlabel("True Label")
plt.ylabel("Count")
plt.xticks(rotation=0)
plt.tight_layout()
plt.show()
