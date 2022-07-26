import time
import weka.core.jvm as jvm
import weka.core.serialization as serialization
from weka.core.converters import Loader
from weka.classifiers import Classifier
from featureExtraction import FeatureExtraction
from mainHandler import *

class URLAnalysis:
  Constructor
    def __init__(self, url):

        self.results_list = []
        self.weka_model = "trained-random-tree.model"
        self.dataset = "url.arff"
        self.url = url
        self.prediction = ""
        
 def href_check(self):

        href_results = []
        count_of_bad_instances = 0

        head = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'}

        # try and use BeautifulSoup to grab the url's corresponding page and get all of the links (hrefs)
        try:

            request = urllib.request.Request(self.url, headers=head)
            page = urllib.request.urlopen(request)
            soupy = BeautifulSoup(page, 'html.parser')

            for a in soupy.find_all('a', href=True):
                href_results.append(a['href'])

            # if there are links
            if len(href_results) > 0:

                # for each link
                for item in href_results:

                    items_domain = tldextract.extract(item).domain  # extract the domain from the link

                    # if the link doesn't go anywhere increase bad instance metric
                    if item == "#":
                        count_of_bad_instances += 1

                    # if the link goes to a different domain increase bad instance metric
                    elif not items_domain == self.domain:
                        count_of_bad_instances += 1

                    # if the link goes to a page on the same domain via ../ or / then decrease bad instance metric
                    elif item.startswith("../"):
                        count_of_bad_instances -= 1

                    elif item.startswith("/"):
                        count_of_bad_instances -= 1

                    # if more than half of the links on the page have been marked as bad
                    if count_of_bad_instances > (0.5 * len(href_results)):
                        self.arff_List.append("BadHREFs")  # append bad to feature list with regards to the links
                        break

                    # else append good to feature list with regards to the links
                    else:
                        self.arff_List.append("GoodHREFs")
                        break

            else:  # else (there are no links) also append bad to feature list with regards to the links
                self.arff_List.append("BadHREFs")

        # if an error occurs append error to the feature list
        except Exception as e:
            self.arff_List.append("ErrorHREFs")        
