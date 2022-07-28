import os
import pyfiglet
import requests
from termcolor import colored
from tldextract import tldextract
from whiteBlacklist import WhiteBlackApp
from urlAnalysis import URLAnalysis


# handling of data, running of tests against urls
class MainHandler:

    # Constructor
    def __init__(self, url):

        # initialise variables
        self.url = url
        self.domain = ""
        self.id = ""
        self.show_banner()


    # function which extracts the domain from the url using tldextract
    def extract_domain(self):

        self.domain = tldextract.extract(self.url).domain

    # navigating the final destination of the URL
    def get_url(self):

        # add http:// on front of the url if it doesn't have a scheme (requried so that the final url's location can be determined)
        if not self.url.startswith("http"):
            self.url = "http://" + self.url

        # try to work out the final destination of the url using the requests library. A header has been added so that
        # websites believe that the request is legit traffic.
        head = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'}
        try:
            request = requests.get(self.url, headers=head)

            # set the url to that resolved by the requests library and call the run ("main") function
            self.url = request.url

        # exception: if the website is not live exit 
        except Exception as e:

            os.system("clear")
            self.show_banner()
            print("URL: " + colored(self.url, 'white') + "\n")
            print(colored("[*]  ERROR: The url is NOT VALID  [*]\n", 'orange'))
            exit()

     # main function
def run(self):
    self.get_url()
    # print the url 
    print("URL: " + colored(self.url, 'white') + "\n")

    self.extract_domain()  # call function to determine the domain associated with the url

    # run white and blacklist tests from WhiteBlack class against the url
    white_black_test = WhiteBlackApp(self.url, self.domain)
    white_black_results = white_black_test.run()

    # if the blacklist test has been failed, print FAIL message
    if white_black_results[0]:

        # UI
        print(colored("\n[*] THE URL HAS BEEN DETERMINED AS SUSPICIOUS [*]\n", 'red', attrs=['bold']))

    # else if the whitelist test has been passed, print PASS message
    elif white_black_results[1]:

        # UI
        print(colored("\n[*] THE URL HAS BEEN DETERMINED AS NOT SUSPICIOUS [*]\n", 'green', attrs=['bold']))

    # else call URLAnalysis class and use its functions to determine if the url is "suspicious" or not via
    # feature extraction and machine learning
    else:

        result = URLAnalysis(self.url)
        ml_result = result.run()

        # if the result returned from URLAnalysis is 1.0 ("suspicious"), print FAIL message
        if ml_result:

            # UI
            print(colored("\n[*] THE URL HAS BEEN DETERMINED AS SUSPICIOUS VIA MACHINE LEARNING [*]\n", 'red',
                          attrs=['bold']))

        # else print PASS message
        else:

            # UI
            print(colored("\n[*] THE URL HAS BEEN DETERMINED AS NOT SUSPICIOUS VIA MACHINE LEARNING [*]\n", 'green', attrs=['bold']))       
    
    
    
    def show_banner(self):
        os.system("clear")
        print(pyfiglet.figlet_format("'PhishEye'"))
        print("----------------------------------------------------------\n")        


