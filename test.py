# Development branch
from burp import IBurpExtender
from burp import IParameter
from burp import IExtensionHelpers
from burp import IRequestInfo
from burp import IResponseInfo
from burp import IProxyListener
from burp import ICookie
from burp import IScanIssue
from burp import IScannerListener
from burp import IInterceptedProxyMessage
from threading import Lock

from java.net import URL
from java.io import PrintWriter



class BurpExtender(IBurpExtender, IProxyListener, IScannerListener):
    def registerExtenderCallbacks(self, callbacks):
       
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._lock = Lock()

        
        # set our extension name
        callbacks.setExtensionName('Test Scan')
               
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # register ourselves as a Proxy listener
        #callbacks.registerProxyListener(self)          # Done for now
        #callbacks.registerScannerListener(self)
               
        # AUTO ADD TO SCOPE ------- TESTING PURPOSE ONLY
        #callbacks.includeInScope(URL("https://202.176.197.54"))
        #callbacks.includeInScope(URL("https://stg-home.singpass.gov.sg"))
        #callbacks.includeInScope(URL("http://192.168.119.130:3000"))
        #self.getScanIssues()
        
        self._stdout.println('Loaded Extension.')

    #
    # implement IProxyListener
    #            
    def processProxyMessage(self, messageIsRequest, message):
        # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :
            request = message.getMessageInfo().getRequest()
            requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())

            directory = requestInfo.getHeaders()[0].split(' ')[1]
            host = "www.evil.com"
            port = 80
            request = self._helpers.buildHttpRequest(URL("http://" + host + directory))
            response = self._callbacks.makeHttpRequest(host, port, False, request)
            responseInfo = self._helpers.analyzeResponse(response)
            print responseInfo.getStatusCode()
            
            
            
            
            
    def getScanIssues(self):
        scannedIssues = self._callbacks.getScanIssues("http://204.197.157.18:8080")
        self._stdout.println("Size of scanned issues on this url: " + str(len(scannedIssues)))
        
        repeatedIssue = []

        for issue in scannedIssues:
            if issue.getIssueName() not in repeatedIssue: 
                self._stdout.println(issue.getSeverity())
                self._stdout.println(issue.getConfidence())
                self._stdout.println("Issue Name: " + issue.getIssueName())
                repeatedIssue.append(issue.getIssueName())
                self._stdout.println()

          
    # implement IscannerListener
    def newScanIssue(self, issue):
        self._stdout.println("Severity: " + issue.getSeverity())
        self._stdout.println("Confidence: " + issue.getConfidence())   
        self._stdout.println("Issue Name: " + issue.getIssueName())        
        self._stdout.println("IssueBackground: " + issue.getIssueBackground())  
        self._stdout.println("Details: " + issue.getIssueDetail())
        self._stdout.println("Remediation Background: " + issue.getRemediationBackground())
        self._stdout.println("Remediation Background: " + issue.getRemediationDetail())
        self._stdout.println()
        
    #
	# @params IParameter Type
	#
	def paramType(self, type):
		plist = {
			IParameter.PARAM_BODY: '[Body]',
			IParameter.PARAM_COOKIE: '[Cookie]',
			IParameter.PARAM_JSON: '[Json]',
			IParameter.PARAM_MULTIPART_ATTR: '[Multipart]',
			IParameter.PARAM_XML: '[Xml]',
			IParameter.PARAM_XML_ATTR: '[Xml Attr]'
		}
		return plist[type]
        
        
    '''
    #
    # implement IHttpListener
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo): 
        reqInfo = self._helpers.analyzeRequest(messageInfo.getHttpService() , messageInfo.getRequest())
        self._numOfParams = len(reqInfo.getParameters())
        
        if self._callbacks.isInScope(reqInfo.getUrl()) :
            self._stdout.println(("HTTP in scope: " + str(reqInfo.getUrl())))
        
    #
    # implement IProxyListener
    #            
    def processProxyMessage(self, messageIsRequest, message):
        # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :

            # check if message is an request
            if messageIsRequest:
                self._stdout.println("OUTGOING REQUEST")
                requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
                self._stdout.println(("HTTP request to " + str(requestInfo.getUrl())))
            else:
                self._stdout.println("INCOMING RESPONSE")
                responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
                self._stdout.println("HTTP response header :" + str(responseInfo.getHeaders()))
                
                
                
                
    # FOR PORT 80
    # implement IProxyListener(boolean messageIsRequest, IInterceptedProxyMessage message)
    #            |------> IInterceptedProxyMessage to get IHttpRequestResponse use getMessageInfo() 
    def processProxyMessage(self, messageIsRequest, message):

                
        # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :
        
            if (message.getMessageInfo().getHttpService().getPort() == 80):
                self._stdout.println("Send on 80 :" + message.getMessageInfo().getHttpService().getHost())
        
            #self._stdout.println("Message ID# :" + str(message.getMessageReference()))
            # check if message is an request
            if messageIsRequest:
                requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
                #self._stdout.println(("HTTP request to " + str(requestInfo.getUrl())))
            else:
                responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
                #self._stdout.println("Response header :" + str(responseInfo.getStatusCode()))
     
        
    # work done to capture server info leakage
    def processProxyMessage(self, messageIsRequest, message):
        # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :
            # check if message is an request
            if messageIsRequest:
                requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
                #self._stdout.println(("HTTP request to " + str(requestInfo.getUrl())))
            else:
                responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
                headerList = responseInfo.getHeaders()
                for header in headerList: 
                    tokens = header.split(":")
                    if "server" in header.lower() and len(tokens[1]) != 1:
                            self._stdout.println("Server Details:" + tokens[1])
                            #self._stdout.println("Server length:" + str(len(tokens[1])))

    
    # work done to capture scanner issues
    # implement IProxyListener(boolean messageIsRequest, IInterceptedProxyMessage message)
    #            |------> IInterceptedProxyMessage to get IHttpRequestResponse use getMessageInfo() 
    def processProxyMessage(self, messageIsRequest, message):
        # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :
            # check if message is an request
            if messageIsRequest:
                requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
                #self._stdout.println(("HTTP request to " + str(requestInfo.getUrl())))
            else:
                responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
                responseHeaderList = responseInfo.getHeaders()
                
                
                for header in responseHeaderList:
                    if "cookie" in header.lower():
                        self._stdout.println(str(header))
                        
                        if ("secure" in header.lower() and "httponly" in header.lower()):
                            self._stdout.println("Secure and HTTPOnly cookie flags are implemented")
                        elif ("secure" in header.lower()):
                            self._stdout.println("Secure cookie flags is implemented")
                        elif ("httponly" in header.lower()):
                            self._stdout.println("HTTPOnly cookie flags is implemented")
                        else:
                            self._stdout.println("No cookie flags implemented")
                        self._stdout.println()

    # Work done on Cookie flag
    # implement IProxyListener(boolean messageIsRequest, IInterceptedProxyMessage message)
    #            |------> IInterceptedProxyMessage to get IHttpRequestResponse use getMessageInfo() 
    def processProxyMessage(self, messageIsRequest, message):
        # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :
            # check if message is an request
            if messageIsRequest:
                requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
                #self._stdout.println(("HTTP request to " + str(requestInfo.getUrl())))
            else:
                responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
                responseHeaderList = responseInfo.getHeaders()
                
                
                for header in responseHeaderList:
                    if "cookie" in header.lower():
                        self._stdout.println(str(header))
                        
                        if ("secure" in header.lower() and "httponly" in header.lower()):
                            self._stdout.println("Secure and HTTPOnly cookie flags are implemented")
                        elif ("secure" in header.lower()):
                            self._stdout.println("Secure cookie flags is implemented")
                        elif ("httponly" in header.lower()):
                            self._stdout.println("HTTPOnly cookie flags is implemented")
                        else:
                            self._stdout.println("No cookie flags implemented")
                        self._stdout.println()
                
    '''