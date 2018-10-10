# Development Branch

from burp import IBurpExtender
from burp import ITab
from burp import IProxyListener
from burp import IMessageEditorController
from burp import IParameter
from burp import IRequestInfo
from burp import IResponseInfo
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
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
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
        headerList = responseInfo.getHeaders()
        toLog = False
        
        # Capture Port 80 Request   
        if (message.getMessageInfo().getHttpService().getPort() == 80):
            self._stdout.println("Send on 80 :" + message.getMessageInfo().getHttpService().getHost())
            toLog = True
            
        

        for header in headerList: 
            tokens = header.split(":")
            # Capture information if there is a server response header
            if "server" in header.lower() and len(tokens[1]) != 1:
                self._stdout.println("Server Details:" + tokens[1])
                toLog = True
            
            # Capture information if there is a server information leakage
            if "x-powered-by" in header.lower() and len(tokens[1]) != 1:
                self._stdout.println("Web Server powered by :" + tokens[1])
                toLog = True
            
            
            # Check for security headers that enforces security endpoint web browsers
            # Reference to: https://www.owasp.org/index.php/REST_Security_Cheat_Sheet
            #
            if "x-content-type-options" in header.lower() and tokens[1] !=  " nosniff":
                self._stdout.println("Potential XSS content type")
                toLog = True
                
            if "x-frame-options" in header.lower() and ( tokens[1] !=  " deny" or tokens[1] != " SAMEORIGIN" ):
                self._stdout.println("Web vulneranle to  drag'n drop clickjacking attacks in older browsers")
                toLog = True
            
            if "content-type" in header.lower() and ("text/html" not in token[1]) :
                self._stdout.println("Malicious content type headers in your response")
                toLog = True
            
        if(toLog):
            self._log.add(LogEntry(self._callbacks.TOOL_PROXY, self._callbacks.saveBuffersToTempFiles(message.getMessageInfo()), self._helpers.analyzeRequest(message.getMessageInfo()).getUrl()))
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
# Object Class for requirment
#
class Requirements:
    def __init__(self):
        self.UNENCRYPTED_CHANNEL = False
        
    def flagUnencrypted(self):
        self.UNENCRYPTED_CHANNEL = True
        
    def checkFlagUnencrypted(self):
        if (self.UNENCRYPTED_CHANNEL):
            return "UNENCRYPTED_CHANNEL"
        return
        
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
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#
class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url