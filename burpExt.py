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
from threading import Lock
from java.net import URL


class BurpExtender(IBurpExtender, ITab, IProxyListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
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
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
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
        headerList = responseInfo.getHeaders()
        toLog = False
        logMsg = "";
        # Capture Port 80 Request   
        if (message.getMessageInfo().getHttpService().getPort() == 80):
            logMsg += "[+] Send on 80 :" + message.getMessageInfo().getHttpService().getHost() + "\n"
            toLog = True
            
            if responseInfo.getStatusCode() < 300:
                logMsg += "[+] Server Return 2xx Success Message from a HTTP Request detected, potential sensitive information being transmitted over non-SSL connections\n"
            elif ((responseInfo.getStatusCode() == 302) or (responseInfo.getStatusCode() == 301) or (responseInfo.getStatusCode() == 304) ) :
                logMsg += "[+] Server Return "+ responseInfo.getStatusCode() +" Redirection Message from a HTTP Request detected\n"

            

        for header in headerList: 
            tokens = header.split(":")
            # Capture information if there is a server response header
            if "server" in header.lower() and len(tokens[1]) != 1:
                logMsg += "[+] Potential Server Details:" + tokens[1] + "\n"
                toLog = True
            
            # Capture information if there is a server information leakage
            if "x-powered-by" in header.lower() and len(tokens[1]) != 1:
                logMsg += "[+] Web Server powered by :" + tokens[1] + "\n"
                toLog = True
            
            
            # Check for security headers that enforces security endpoint web browsers
            # Reference to: https://www.owasp.org/index.php/REST_Security_Cheat_Sheet
            #
            if "x-content-type-options" == header.lower() and "nosniff" not in tokens[1].lower():
                logMsg += "[+] Potential XSS content type\n"
                toLog = True
                
            if "x-frame-options" == header.lower():
                if "sameorigin" not in tokens[1].lower() or "deny" not in tokens[1].lower():
                    logMsg += "[+] Web vulneranle to  drag'n drop clickjacking attacks in older browsers\n" 
                    toLog = True
            
            if "content-type" == header.lower(): 
                if "text/html" not in tokens[1].lower():
                    logMsg += "[+] Potential malicious content type headers in your response\n"
                    toLog = True
         
        # Capture Cookie 

         
        if(toLog):
            log = LogEntry(self._callbacks.TOOL_PROXY, self._callbacks.saveBuffersToTempFiles(message.getMessageInfo()), self._helpers.analyzeRequest(message.getMessageInfo()).getUrl(), logMsg)
            self._log.add(log)
            self._stdout.println(logMsg)
            #self._stdout.println("new log entered: " + log._logMsg)
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