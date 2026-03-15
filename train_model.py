import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

# Features: [URL Length, Domain Age (days), Num Subdomains, HTTPS (1=Yes, 0=No), Blacklisted (1=Yes, 0=No)]
# Labels: 0 (Safe), 1 (Phishing)

# Safe websites (length < 60, older than 365 days, 0-1 subdomains, https=1, blacklist=0)
safe_data = np.array([
    [25, 400, 0, 1, 0],
    [30, 1000, 1, 1, 0],
    [20, 365, 0, 1, 0],
    [45, 2000, 0, 1, 0],
    [22, 500, 0, 1, 0],
    [50, 800, 1, 1, 0],
    [32, 1200, 0, 1, 0],
    [28, 900, 0, 1, 0],
    [21, 1500, 0, 1, 0],
    [15, 600, 0, 1, 0]
])
safe_labels = np.array([0] * len(safe_data))

# Phishing websites (length > 70 OR domain < 30 days OR 2+ subdomains OR https=0 OR blacklist=1)
phish_data = np.array([
    [85, 2, 3, 0, 1],
    [75, 5, 2, 0, 0],
    [90, 1, 4, 1, 1],
    [25, 10, 0, 0, 1],
    [65, 15, 2, 0, 0],
    [100, 3, 5, 1, 0],
    [80, 7, 3, 0, 1],
    [60, 20, 2, 0, 0],
    [120, 1, 6, 0, 1],
    # Edge cases like amazon.cin/kk (short, very young/0 age, 0 subdomains, HTTPS, not explicitly blacklisted)
    [21, 0, 0, 1, 0], 
    [30, 5, 1, 1, 0], 
    [40, 2, 0, 1, 0],
    [15, 0, 0, 1, 0],
    [25, 10, 0, 1, 0]
])
phish_labels = np.array([1] * len(phish_data))

# Combine dataset
X = np.vstack((safe_data, phish_data))
y = np.concatenate((safe_labels, phish_labels))

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

joblib.dump(model, 'phishing_rf_model.pkl')
print("Model retrained effectively for edge cases and saved to phishing_rf_model.pkl")
