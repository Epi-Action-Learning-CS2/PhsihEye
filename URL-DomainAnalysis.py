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
    def __init__(self, url):

        self.results_list = []
        self.weka_model = "trained-random-tree.model"
        self.dataset = "url.arff"
        self.url = url
        self.prediction = ""


# It is a function that  calls a function from a different class and the features will be extracted from the URL and saved to .arff file
    def generate_arff(self):

        extract = FeatureExtraction()

        extract.run()

        time.sleep(0.5)  # sleep is used to make sure everything runs smoothly

    # It is a function that generates a .csv file and appends the url which will be tested into it
    def generate_csv(self):
        with open("url.csv", "w+") as file:
            file.write(self.url)

        file.close()

    # main function
    def run(self):
        jvm.start()  # JAVA VM for WEKA will start

        self.show_banner()  # call function to draw the banner on the UI
        self.generate_csv()  # The URL that will be tested which is found in the csv file will be called using this function
        self.generate_arff()  # a call function that calls a function from a different class and the features will be extracted from the URL and saved to .arff file
        self.show_banner()  # call function to draw the banner on the UI
        self.weka_predict()  # a call function that predicts whether the url/domain is malicious or not via the .arrf files

        jvm.stop()

        return self.prediction  # restore the predicted result back to MainHandler

    # This function is used to show an ASCII banner on the console
    # (Did not use the MainHandler because it caused the Java VM and WEKA to bug out)
    def show_banner(self):
        os.system("clear")
        print(pyfiglet.figlet_format("'PhishEye'"))
        print("----------------------------------------------------------\n")
        print("URL: " + colored(self.url, 'white') + "\n")

    # a function that determines whether the/domain url is malicious or not by testing the .arff file on a trained Random Tree WEKA model
    def weka_predict(self):

        # grab WEKA model
        objects = serialization.read_all(self.weka_model)
        classifier = Classifier(jobject=objects[0])

        # load the dataset which implies the .arff file generated for the supplied url/domain
        loader = Loader(classname="weka.core.converters.ArffLoader")
        data = loader.load_file(self.dataset)
        data.class_is_last()

        # for each url/domain tested predict whether malicious or not by using the Random Tree model
        for item in data:
            self.prediction = classifier.classify_instance(item)
