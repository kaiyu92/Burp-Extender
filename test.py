# Development branch
from burp import IBurpExtender
from burp import IParameter
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
    def registerExtenderCallbacks( self, callbacks):
       
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
        callbacks.registerScannerListener(self)
        
        
        self._stdout.println('Loaded Extension.')
        
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
            
    # implement IscannerListener
    def newScanIssue(self, issue):
        background = issue.getIssueName()
        self._stdout.println("New Scan Issue: " + background)                 
                        
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
 

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


 
        
        
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