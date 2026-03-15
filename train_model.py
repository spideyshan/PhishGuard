import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

# We generate some dummy data for training the model based on expected features.
# Features: [URL Length, Domain Age (days), Num Subdomains, HTTPS (1=Yes, 0=No), Blacklisted (1=Yes, 0=No)]
# Labels: 0 (Safe), 1 (Phishing)

# Safe websites (length < 50, older than 365 days, 0-1 subdomains, https=1, blacklist=0)
safe_data = np.array([
    [25, 400, 0, 1, 0],
    [30, 1000, 1, 1, 0],
    [20, 365, 0, 1, 0],
    [45, 2000, 0, 1, 0],
    [22, 500, 0, 1, 0],
    [50, 800, 1, 1, 0],
    [32, 1200, 0, 1, 0],
    [28, 900, 0, 1, 0],
    [21, 1500, 0, 1, 0]
])
safe_labels = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0])

# Phishing websites (length > 70 or young domain < 30 days, 2+ subdomains, https=0, blacklist=1 sometimes)
phish_data = np.array([
    [85, 2, 3, 0, 1],
    [75, 5, 2, 0, 0],
    [90, 1, 4, 1, 1],
    [25, 10, 0, 0, 1],
    [65, 15, 2, 0, 0],
    [100, 3, 5, 1, 0],
    [80, 7, 3, 0, 1],
    [60, 20, 2, 0, 0],
    [120, 1, 6, 0, 1]
])
phish_labels = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1])

# Combine dataset
X = np.vstack((safe_data, phish_data))
y = np.concatenate((safe_labels, phish_labels))

# Train a Random Forest Model
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X, y)

# Save the model
joblib.dump(model, 'phishing_rf_model.pkl')
print("Model trained and saved to phishing_rf_model.pkl")
