import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# Load the preprocessed dataset
data = pd.read_csv('UNSW_NB15_training-set.csv')

# Drop unnecessary columns
data = data.drop(['id', 'attack_cat'], axis=1)

# Convert categorical variables to numerical
for column in data.select_dtypes(include='object').columns:
    data[column] = pd.factorize(data[column])[0]

# Split into features and labels
X = data.iloc[:, :-1]
y = data.iloc[:, -1]

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Scale the features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Convert the data to DMatrix format (required by XGBoost)
dtrain = xgb.DMatrix(X_train, label=y_train)
dtest = xgb.DMatrix(X_test, label=y_test)

# Define the parameters for XGBoost
params = {
    'max_depth': 6,
    'objective': 'multi:softmax',
    'num_class': len(np.unique(y)),
    'eval_metric': 'merror'
}

# Train the XGBoost model
model = xgb.train(params, dtrain)

# Make predictions on the test set
y_pred = model.predict(dtest)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy}')

cr = classification_report(y_test, y_pred)
print(f'Classification Report:\n{cr}')

# Save the trained model as a pretrained model file
model_file = 'pretrained_model.model'
model.save_model(model_file)
