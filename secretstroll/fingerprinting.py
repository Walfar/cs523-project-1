import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score
from scapy.all import *
import os 
import sys


def classify(train_features, train_labels, test_features, test_labels):

    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    
    return predictions

def perform_crossval(features, labels, folds=10):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)

    y_true = np.array()
    y_pred = np.array()
    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test, y_test)
        for prediction,true_value in zip(predictions,y_test) :
            y_pred.append(prediction)
            y_true.append(true_value)


    # View accuracy score
    performance = accuracy_score(y_true, y_pred)
    return performance
    ###############################################
    # TODO: Write code to evaluate the performance of your classifier
    ###############################################

def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """
    feature_selection = {}
    for n in range(1,101) :
        feature_selection[n] = []

    for dir in os.listdir("pcaps") :
        for file in os.listdir(dir) :
            packets = rdpcap("pcaps/"+dir+"/"+file)
            for pkt in packets :
                if pkt[TCP].payload:
                    i = pkt[TCP].load.decode('uft8').find("cell_id=")
                    if i != 1 :
                        cell_id = re.search(r'\d',pkt[TCP].load.decode('uft8')[i:]).group()
            
            bytes_list = list()

            for pkt in packets : 
                pkt[TCP].remove_payload()
                header_length = len(raw(pkt))
                if  header_length == 56 :
                    for b in raw(pkt) : 
                        bytes_list.append(str(b))
                if len(bytes_list) > 25200 :
                    bytes_list = bytes_list[:25200]
                if(len(bytes_list) == 25200) :
                    feature_selection[cell_id].append(bytes_list)

                         

    ###############################################
    # TODO: Complete this function. 
    ###############################################

    features = []
    labels = []
    for (grid_id,bytes_features) in feature_selection :
        features.append(bytes_features)
        labels.append(grid_id)

    return features, labels
        
def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    perform_crossval(features, labels, folds=10)
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)