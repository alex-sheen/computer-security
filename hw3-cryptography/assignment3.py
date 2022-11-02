import urllib.request
import base64
from pymd5 import md5, padding
################################################################################
#
# This starter file for UChicago CMSC 23200 / 33250 is for Python3
#
################################################################################
################################################################################
#
# make_query(cnet_id, query)
# -- cnet_id should always be your own cnet_id
# -- query can be any string of bytes, including non-printable
#
# Must be run "on campus" or within the VPN, otherwise it will hang.
#
################################################################################
SERVER = "http://securityclass.cs.uchicago.edu/"
def make_query(cnet_id, query):
    DEBUG = False; # Replace with "True" to print extra debugging information
    cnet_id = cnet_id.lower()
    if DEBUG:
        print("Querying the server")
        print("(CNET ID:", cnet_id, ")")
        print("(Query:", query, ")")
    if (type(query) is bytearray) or (type(query) is bytes):
        url = SERVER + urllib.parse.quote_plus(cnet_id) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query)) + "/"
    else:
        url = SERVER + urllib.parse.quote_plus(cnet_id) + "/" + urllib.parse.quote_plus(base64.urlsafe_b64encode(query.encode('utf-8'))) + "/"
    if DEBUG:
        print("(Querying:", url, ")")
    with urllib.request.urlopen(url) as response:
       answer = base64.urlsafe_b64decode(response.read())
       return answer
################################################################################
# Helper methods, if needed, go below here
################################################################################
#your code here
################################################################################
# PROBLEM 1 SOLUTION
################################################################################
def problem1():
    cnet = "alexsheen"
    url = make_query(cnet, "")
    print("\nStart URL: " + url.decode('UTF-8'))
    params_str = params_strs = url.lstrip(b'http://www.flickur.com/?')
    ps = list(map(lambda x: x.split(b'='), params_strs.split(b'&')))
    params = {p[0]: p[1] for p in ps if len(p) >= 2}
    prev_tag = params[b'api_tag']
    print("\nprev_tag: " + prev_tag.decode('UTF-8'))
    h = md5(state=bytes.fromhex(prev_tag.decode('UTF-8')), count=512)
    h.update(b'&role=admin')
    new_digest = h.hexdigest()
    new_url = b'http://www.flickur.com/?api_tag=' + new_digest.encode('UTF-8') + b'&uname=alexsheen&role=user&role=admin'
    i= 0
    while (i<=999999):
        print(i)
        new_url = b'http://www.flickur.com/?api_tag=' + new_digest.encode('UTF-8') + b'&uname=alexsheen&role=user' + padding(i) + b'&role=admin'
        if (make_query(cnet, new_url) != b'Incorrect hash'):
            print("hit!")
            print(make_query(cnet, new_url).decode('UTF-8'))
            return new_url
    i += 1
    print("failed")
    return new_url
    
# Code below here will be run if you execute 'python3 assignment3.py'.
# This code here won't be graded, and your code above shouldn't depend on it.
if __name__ == "__main__":
  problem1()
  # optional driver code here
  exit()