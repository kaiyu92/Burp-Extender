# Development Branch

from burp import IBurpExtender
from burp import ITab
from burp import IProxyListener
from burp import IMessageEditorController
from burp import IParameter
from burp import IRequestInfo
from burp import IResponseInfo
from burp import ICookie
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from javax.swing import JTextPane;
from javax.swing import JPanel
from threading import Lock
from java.net import URL
import base64
#import re


class BurpExtender(IBurpExtender, ITab, IProxyListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    # custom flags
    
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Scanner Beta")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # Custom logging flags
        self._secHeaderFlag = False
        self._cookieFlag = False
        self._httpRequestFlag = False
        self._basicAuthenticationFlag = False
        self._serverDetailFlag = False 
         
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        

        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self._logMsgViewer = JTextPane()
        self._logMsgViewer.setEditable(False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        tabs.addTab("Logged Flags", self._logMsgViewer)
        self._splitpane.setRightComponent(tabs)
        

        self._mainTab = JTabbedPane()
        self._mainTab.addTab("Logged HTTP Traffic", self._splitpane)
        self._mainTab.addTab("TODO", self._splitpane)
 
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
      

        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Development Scanner"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IProxyListener(boolean messageIsRequest, IInterceptedProxyMessage message)
    #               |------> IInterceptedProxyMessage to get IHttpRequestResponse use getMessageInfo()
    def processProxyMessage(self, messageIsRequest, message):
    # message have to be in scope first
        if self._callbacks.isInScope(URL(message.getMessageInfo().getHttpService().toString())) :
            # only process requests
            if messageIsRequest:
                return
                
            # create a new log entry with the message details
            self._lock.acquire()
            self.logMessage(message)    
            self._lock.release()
        
    #
    # Log the HTTPMessage if falls into requirements
    #
    def logMessage(self, message):
        row = self._log.size()
        
        requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
        responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
        cookieInfo = responseInfo.getCookies()
        requestHeaderList = requestInfo.getHeaders()
        respondHeaderList = responseInfo.getHeaders()
        toLog = False
        logMsg = ""
        inner_sec_flag = False
        partial_cookie_msg = ""
        partial_cookie_flag = False
        
        
        # Capture Port 80 Request   
        if (message.getMessageInfo().getHttpService().getPort() == 80 and self._httpRequestFlag == False):
            logMsg += "[+] Send on 80 :" + message.getMessageInfo().getHttpService().getHost() + "\n"
            toLog = True
            self._httpRequestFlag = True
            
            if responseInfo.getStatusCode() < 300 and responseInfo.getStatusCode() >= 200:
                logMsg += "[+] Server Return 2xx Success Message from a HTTP Request detected, potential sensitive information being transmitted over non-SSL connections\n"
            elif ((responseInfo.getStatusCode() == 302) or (responseInfo.getStatusCode() == 301) or (responseInfo.getStatusCode() == 304) ) :
                logMsg += "[+] Server Return "+ str(responseInfo.getStatusCode()) +" Redirection Message from a HTTP Request detected\n"

        
        # Looking for Server information leakage when GET request without the host header (47)
        # TODO        
        
        # Checking Request Header
        for header in requestHeaderList:
        
            # Capture if there is weak authentication header request 
            #       EXAMPLE:Cookie: Authorization=Basic%20dGVzdDowOThmNmJjZDQ2MjFkMzczY2FkZTRlODMyNjI3YjRmNg%3D%3D
            #       KEY: Look for Authorization=Basic
            #       NOTE:  %20 is equal to "" and %3D = "="
            if self._basicAuthenticationFlag == False and "authorization=basic" in header.lower():
                tokens = header.split(" ")
                text = tokens[1]
                userCredential = text[text.find("0")+1:text.find("%3D%3D")]
                userCredential += "=" * ((4 - len(userCredential) % 4) % 4) #ugh
                decode = base64.b64decode(userCredential)            
                logMsg += "[+] Basic Authentication request is being used, decoded found: " + decode + "\n"
                toLog = True
                self._basicAuthenticationFlag = True
        
        # Checking Response Header
        for header in respondHeaderList: 
            tokens = header.split(":")
            
            # Capture information if there is a server response header
            if "server" in header.lower() and len(tokens[1]) != 1 and self._serverDetailFlag == False:
                logMsg += "[+] Potential Server Details:" + tokens[1] + "\n"
                toLog = True
                self._serverDetailFlag = True
            
            # Capture information if there is a server information leakage
            if "x-powered-by" in header.lower() and len(tokens[1]) != 1:
                logMsg += "[+] Web Server powered by :" + tokens[1] + "\n"
                toLog = True
            
            # Check for security headers that enforces security endpoint web browsers
            # Reference to: https://www.owasp.org/index.php/REST_Security_Cheat_Sheet
            #         
            if (self._secHeaderFlag == False):            
                if "x-content-type-options" == tokens[0].lower():
                    logMsg += "[+] X-Content-Type-Options header implemented\n"
                    inner_sec_flag = True
                    
                if "x-frame-options" == tokens[0].lower():
                    logMsg += "[+] X-Frame-Options implemented\n" 
                    inner_sec_flag = True

                if "x-xss-protection" == tokens[0].lower():
                    logMsg += "[+] X-xss-protection implemented\n" 
                    inner_sec_flag = True

                if "content-type" == tokens[0].lower(): 
                    logMsg += "[+] Content-Type implemented\n"
                    inner_sec_flag = True
                
            
            
            # Check for cookie flag return from server.
            if(self._cookieFlag == False and "set-cookie" in header.lower()):
                if ("secure" in header.lower() and "httponly" in header.lower()):
                    logMsg += "[+] Secure and HTTPOnly cookie flags are implemented\n"
                    self._cookieFlag = True
                    toLog = True
                    
                elif ("secure" in header.lower()):
                    partial_cookie_flag = True
                    partial_cookie_msg = "Only Secure cookie flags is implemented\n"
                    
                elif ("httponly" in header.lower()):
                    partial_cookie_flag = True
                    partial_cookie_msg = "Only HTTPOnly cookie flags is implemented\n"

                    
        if (self._cookieFlag == False):
            if partial_cookie_flag:
                logMsg += partial_cookie_msg
            else:
                logMsg += "[+] No cookie flags implemented\n"
                
            self._cookieFlag = True
            toLog = True
        
        if inner_sec_flag:
            self._secHeaderFlag = True
            toLog = True
        
        
        if(toLog):
            log = LogEntry(self._callbacks.TOOL_PROXY, self._callbacks.saveBuffersToTempFiles(message.getMessageInfo()), self._helpers.analyzeRequest(message.getMessageInfo()).getUrl(), logMsg)
            self._log.add(log)
            self._stdout.println(logMsg)
            self.fireTableRowsInserted(row, row)


    #
    # extend AbstractTableModel
    #
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    #    # this allows our request/response viewers to obtain details about the messages being displayed

    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()
    
    
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
# extend JTable to handle cell selection
#   
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        
        self._extender._logMsgViewer.setText(logEntry._logMsg)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#
class LogEntry:
    def __init__(self, tool, requestResponse, url,logMsg):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._logMsg = logMsg