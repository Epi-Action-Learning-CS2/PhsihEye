import csv
import os
import time
import arff
from urllib.parse import urlparse
import tldextract
from parseTLDList import ParseTLD
from search_engine_parser.core.engines import GoogleSearch, YahooSearch
import urllib.request
from bs4 import BeautifulSoup
import requests
from urllib.request import socket


# Feature extraction
class FeatureExtraction:
    def __init__(self):
        self.url = ""
        self.scheme = ""
        self.domain = ""
        self.path = ""
        self.query = ""
        self.arff_List = []
        self.url_list = []
        self.tld_list = ParseTLD().parse()  # call class function within parseTLDlist.py to create list of all tlds

    # function which determines if the links within the url's corresponding page are characteristic of a phishing page
    def href_check(self):

        href_results = []
        count_of_bad_instances = 0

        head = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'}

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
            
def num_and_special_characters(self):

        char_list_count = ['.', '-', "_", "%", "&", "#"]  # initialise list of characters to search for

        count = 0  # set count of numbers in the url to zero

        # for each item in the list of characters, append the number of occurrences of said character to the feature list
        for character in char_list_count:
            self.arff_List.append(self.url.count(character))

        # if tilde is present in the url append yes to the feature list, else append no
        if "~" in self.url:
            self.arff_List.append("Yes~")

        else:
            self.arff_List.append("No~")

        # if the at symbol is present in the url append yes to the feature list, else append no
        if "@" in self.url:
            self.arff_List.append("Yes@")

        else:
            self.arff_List.append("No@")

        # loop through each character in the url and determine if it is a number
        for character in self.url:

            if character.isdigit():
                count += 1

        self.arff_List.append(count)  # append the number of numbers to the feature list            
