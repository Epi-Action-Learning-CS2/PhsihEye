import time
import weka.core.jvm as jvm
import weka.core.serialization as serialization
from weka.core.converters import Loader
from weka.classifiers import Classifier
from featureExtraction import FeatureExtraction
from mainHandler import *


# Using an already trained module the following class takes the given domain/URL and checks if it is malicious or not
class domainAnalyser:

    #  Constructor
    def __init__(self, domain):

        self.results_list = []
        self.weka_model = "trained-random-tree.model"
        self.dataset = "domain.arff"
        self.url = domain
        self.prediction = ""


# It is a function that  calls a function from a different class and the features will be extracted from the URL and saved to .arff file
    def generate_arff(self):

        extract = FeatureExtraction()

        extract.run()

        time.sleep(0.5)  # sleep is used to make sure everything runs smoothly

