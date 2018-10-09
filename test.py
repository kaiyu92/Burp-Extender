from burp import IBurpExtender
from burp import IParameter
from burp import IRequestInfo
from burp import IResponseInfo
from burp import IProxyListener
from burp import IInterceptedProxyMessage
from threading import Lock

from java.net import URL
from java.io import PrintWriter



class BurpExtender(IBurpExtender, IProxyListener):
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
        callbacks.registerProxyListener(self)          # Done for now
        
        
        self._stdout.println('Loaded Extension.')
        
    #
    # implement IProxyListener
    #            
    def processProxyMessage(self, messageIsRequest, message):
        # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :
            self._lock.acquire()
            self._stdout.println("Message ID# :" + str(message.getMessageReference()))
            # check if message is an request
            if messageIsRequest:
                self._stdout.println("OUTGOING REQUEST")
                requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
                self._stdout.println(("HTTP request to " + str(requestInfo.getUrl())))
            else:
                self._stdout.println("INCOMING RESPONSE")
                responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
                self._stdout.println("HTTP response header :" + str(responseInfo.getStatusCode()))
            self._lock.release()
        
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
    '''