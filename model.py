import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score

# Load preprocessed dataset
df = pd.read_csv('UNSW_NB15_training-set.csv')

# Create feature and target arrays
X = df.drop('label', axis=1).values
y = df['label'].values

# Encode categorical variables
categorical_cols = [col for col in df.columns if df[col].dtype == 'object']
label_encoders = {}
for col in categorical_cols:
    label_encoders[col] = LabelEncoder()
    X[:, df.columns.get_loc(col)] = label_encoders[col].fit_transform(X[:, df.columns.get_loc(col)])

# Split data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Define xgboost parameters
params = {
    'max_depth': [3, 5, 7],
    'learning_rate': [0.01, 0.1, 0.3],
    'n_estimators': [100, 200, 300],
    'objective': ['multi:softmax'],
    'num_class': [len(np.unique(y_train))]
}

# Create xgboost classifier
xgb_model = xgb.XGBClassifier()

# Perform grid search to find the best hyperparameters
grid_search = GridSearchCV(xgb_model, params, cv=5)
grid_search.fit(X_train, y_train)

# Get the best model and print the best hyperparameters
best_model = grid_search.best_estimator_
print("Best Hyperparameters:", grid_search.best_params_)

# Train xgboost model with the best hyperparameters
best_model.fit(X_train, y_train)

# Make predictions on the test set
y_pred = best_model.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

# Save trained model
best_model.save_model('unsw_nb15_xgb_model2.model')
