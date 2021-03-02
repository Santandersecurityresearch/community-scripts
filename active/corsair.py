
'''
This is an adaptation of Corsair Scan (https://github.com/Santandersecurityresearch/corsair_scan) as a ZAP plugin.
This is delivered as an active scan plugin that will resend requests to all the sites captured in ZAP, injecting different origins. Then, it will read the value of Access-Control-Allow-Origin and based on that, it
will assess if CORS is properly configured.
'''

import urlparse
alertTitle = 'Corsair - CORS misconfigured.'
alertDescription = "Cross Origin Resource Sharing (CORS) is misconfigured. \n"
alertRisk = 2
alertReliability = 3
alertSolution = "Configure CORS in a more restrictive way, whitelisting only the sites allowed to access to your domain"
alertInfo = "Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to indicate any other origins (domain, scheme, or port) than its own from which a browser should permit loading of resources."
cweID = 942
wascID = 14

SM_ORIGIN = 'https://scarymonster.com'
SM_ORIGIN_NO_PROTOCOL = 'scarymonster.com'
SM_ORIGIN_DOMAIN = 'scarymonster'

def scanNode(sas, msg):

'''
In this method, we read the request performed and create a new request with a fake origin. Also, if the request already contains an origin header, we perform two extra requests:
 1 - Fake subdomain. It is, we set as origin a fake subdomain to validate if CORS is configured at domain level, or if it has granularity at subdomain level.
 2 - Fake postdomain. Here, we set a request using the existing origin as a subdomain for a fake domain. We do it to validate if CORS is misconfigured and it only checks if the expected value exists in the origin header.
Then, we call cors_scan, which will send that request and validate the response
'''
  origMsg = msg
  msg = origMsg.cloneRequest()
  
  msg.getRequestHeader().setHeader("Origin", SM_ORIGIN)
  cors_scan(sas,msg, "fake origin")
  if origMsg.getRequestHeader().getHeader('Origin'):
    parsed_url = urlparse.urlparse(origMsg.getRequestHeader().getHeader('Origin'))
    subdomain= parsed_url.scheme + '://' + SM_ORIGIN_DOMAIN + '.' + parsed_url.netloc
    postdomain = origMsg.getRequestHeader().getHeader('Origin') + '.' + SM_ORIGIN_NO_PROTOCOL
    msg.getRequestHeader().setHeader("Origin", subdomain)
    cors_scan(sas,msg, "fake subdomain")
    msg.getRequestHeader().setHeader("Origin", postdomain)
    cors_scan(sas,msg, "fake postdomain")

def cors_scan(sas,msg, test_type):
'''
cors_scan sends the request crafted by scanNode and reads the value of the Access-Control-Allow-Origin header. If it is the origin reflected, * or NULL, we consider that CORS is misconfigured and raise an alert
'''
  sas.sendAndReceive(msg, True, False);
  header = str(msg.getResponseHeader().getHeader("Access-Control-Allow-Origin"))
  if (header in ['null', '*', msg.getRequestHeader().getHeader('Origin')]):
    alertParam = "Test performed: Injecting a "+test_type
    sas.raiseAlert(alertRisk, alertReliability, alertTitle, alertDescription + alertParam,  msg.getRequestHeader().getURI().toString(), "Origin",
       "Origin set as " + msg.getRequestHeader().getHeader('Origin'), alertInfo, alertSolution, header + " returned in Access-Control-Allow-Origin header", cweID, wascID, msg);

def scan(sas, msg, param, value):
  pass
