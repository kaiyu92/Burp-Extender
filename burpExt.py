# Development Branch
try:
    import xlsxwriter
    import shutil
    from burp import IBurpExtender
    from burp import ITab
    from burp import IProxyListener
    from burp import IMessageEditorController
    from burp import IParameter
    from burp import IRequestInfo
    from burp import IResponseInfo
    from burp import ICookie
    from burp import IScanIssue
    from burp import IScannerListener
    from java.awt import Component
    from java.awt import GridLayout
    from java.io import PrintWriter
    from java.util import ArrayList
    from java.util import List
    from javax.swing import JScrollPane
    from javax.swing import JSplitPane
    from javax.swing import JTabbedPane
    from javax.swing import JTable;
    from javax.swing import SwingUtilities
    from javax.swing.table import AbstractTableModel
    from javax.swing import JTextPane
    from javax.swing import JPanel
    from javax.swing import JLabel
    from javax.swing import JTextField
    from javax.swing import JButton
    from javax.swing import ButtonGroup
    from javax.swing import JRadioButton
    from javax.swing import JCheckBox
    from javax.swing import JFileChooser
    from javax.swing import SwingConstants
    from javax.swing.border import EmptyBorder
    from java.io import File
    from java.awt import (BorderLayout,FlowLayout)
    from threading import Lock
    from java.net import URL
    from java.lang import System as System
    import base64
    from bs4 import BeautifulSoup
    '''
    import openpyxl
    import sys
    sys.path.append("C:\Users\winston\Desktop\burpExt\lib\poi-4.0.0.jar")
    from org.apache.poi.hssf.usermodel import *
    '''
    
except ImportError as e:
    print e
    #print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

class BurpExtender(IBurpExtender, ITab, IProxyListener, IMessageEditorController, IScannerListener):
    
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
        self._scanLog = ArrayList()
        self._lock = Lock()
        self._repeatedIssue = []
        self._destDir = File(System.getProperty("java.io.tmpdir"))
        
        # Scan Classification list
        self._xssIssues = ["JavaScript injection (DOM-based)" , "JavaScript injection (reflected DOM-based)" , "JavaScript injection (stored DOM-based)" , "Cross-site request foregery", "Cross-site scripting (DOM-based)" , "Cross-site scripting (reflected DOM-based)" , "Cross-site scripting (reflected)" , "Cross-site scripting (stored DOM-based)" , "Cross-site scripting (stored)" , "Server-side JavaScript code injection" ]
        
        self._sqlIssues = ["SQL injection" , "SQL injection (second order)" , "Client-side SQL injection (DOM-based)" , "Client-side SQL injection (reflected DOM-based)" , "Client-side SQL injection (stored DOM-based)" ]
        self._ldapIssues = ["LDAP injection"]
        self._ssiIssues = ["SSI injection"]
        self._imapSmtpIssues = ["SMTP header injection"]
        self._osCommandIssues = ["OS command injection"]
        self._sourceCodeIssues = ["Source code disclosure"]
        self._webDirIssues = ["Directory Listing & File path traversal"]
        self._xmlFlashHTMLIssues = ["XML injection" , "XPath injection" , "HTTP response header injection" ]
        self._cacheableIssues = ["Cacheable HTTPS response"]
        self._cookieIssues = ["Cookie manipulation (DOM-based)" , "Cookie manipulation (reflected DOM-based)" , "Cookie manipulation (stored DOM-based)" , "Cookie scoped to parent domain" , "Cookie without HttpOnly flag set" ]
        
        # Custom logging flags
        self._secHeaderFlag = False
        self._cookieOverallFlag = False
        self._httpRequestFlag = False
        self._basicAuthenticationFlag = False
        self._serverDetailFlag = False 
         
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # customize our UI components
        self._mainTab = JTabbedPane()
        
        ############## Tab for Traffic logging split pane ############## 
        self._trafficSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        self._logModel = logModel(self)
        self._logTable = Table(self, self._logModel)
        scrollPane = JScrollPane(self._logTable)
        self._trafficSplitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        trafficTabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self._logMsgViewer = JTextPane()
        self._logMsgViewer.setEditable(False)
        self._evidenceViewer = JTextPane()
        self._evidenceViewer.setEditable(False)
        trafficTabs.addTab("Request", self._requestViewer.getComponent())
        trafficTabs.addTab("Response", self._responseViewer.getComponent())
        trafficTabs.addTab("Logged Flags", self._logMsgViewer)
        trafficTabs.addTab("Evidence", self._evidenceViewer)
        self._trafficSplitpane.setRightComponent(trafficTabs)
        self._mainTab.addTab("HTTP Traffic Logs", self._trafficSplitpane)
        
        #################################################################
        

        ############## Tab for Scanning logging split pane ############## 
        self._scanningSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._internalScanningSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._topPanel = JPanel(BorderLayout(10, 10))
        self._topPanel.setBorder(EmptyBorder(0, 0, 10, 0))
        
        # table of scanner entries
        self._scanModel = scanModel(self)
        self._scanTable = ScanTable(self, self._scanModel)
        scanScrollPane = JScrollPane(self._scanTable)
        scanScrollPane.setBorder(EmptyBorder(0, 0, 50, 0))
        
        # Setup Panel :    [Target: ] [______________________] [START BUTTON]
        self.setupPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.setupPanel.add(JLabel("Target:", SwingConstants.LEFT), BorderLayout.LINE_START)
        self.hostField = JTextField('', 50)
        self.setupPanel.add(self.hostField)
        self.toggleButton = JButton('Start scanning', actionPerformed=self.getScanIssues)
        self.setupPanel.add(self.toggleButton)
        # Status bar
        self.scanStatusPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.scanStatusPanel.add(JLabel("Status: ", SwingConstants.LEFT))
        self.scanStatusLabel = JLabel("Ready to scan", SwingConstants.LEFT)
        self.scanStatusPanel.add(self.scanStatusLabel)
        # Add setup panel and status panel to top panel
        self._topPanel.add(self.setupPanel, BorderLayout.PAGE_START)
        self._topPanel.add(self.scanStatusPanel, BorderLayout.LINE_START)
        
        self._internalScanningSplitpane.setLeftComponent(self._topPanel)
        self._internalScanningSplitpane.setRightComponent(scanScrollPane)
        self._scanningSplitpane.setLeftComponent(self._internalScanningSplitpane)
        
        
        # tabs with request/response viewers
        scannerTabs = JTabbedPane()
        self._requestViewer2 = callbacks.createMessageEditor(self, False)
        self._responseViewer2 = callbacks.createMessageEditor(self, False)
        self._scanMsgViewer = JTextPane()
        self._scanMsgViewer.setContentType("text/html")
        self._scanMsgViewer.setEditable(False)
        self._scanMsgViewerScrollPane = JScrollPane(self._scanMsgViewer)
        scannerTabs.addTab("Advisory", self._scanMsgViewerScrollPane)
        scannerTabs.addTab("Request", self._requestViewer2.getComponent())
        scannerTabs.addTab("Response", self._responseViewer2.getComponent())
        self._scanningSplitpane.setRightComponent(scannerTabs)
        self._mainTab.addTab("Scanner Logs", self._scanningSplitpane)
        #################################################################



        ################### Tab for Report Generation ################### 
        self._reportGenSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        self._reportGenComponent = JPanel()
        self._innerPanel = JPanel(GridLayout(2,2,2,0))
        
        # Todo output directory
        self._innerPanel.add(JLabel("Report Output Root Directory:" , SwingConstants.RIGHT))
		
        self._destDirChooser = JFileChooser()
        self._destDirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        dirPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        destDirButton = JButton("Select folder ...", actionPerformed=self.getDirectoryPath)
        self._destDirLabel = JLabel(self._destDir.getAbsolutePath())
        dirPanel.add(destDirButton)
        dirPanel.add(self._destDirLabel)
        self._innerPanel.add(dirPanel)
        
        
        # generate report
        generateButton = JButton("Generate Report" , actionPerformed=self.generateReport)
        self._innerPanel.add(generateButton);
        self._statusLabel = JLabel()
        self._innerPanel.add(self._statusLabel)

        self._reportGenComponent.add(self._innerPanel)
        self._mainTab.addTab("Report Generation", self._reportGenComponent)
      
        #################################################################
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)  
        callbacks.customizeUiComponent(self._mainTab)

        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self) 
        return
    
    def getDirectoryPath(self, event):
        res = self._destDirChooser.showOpenDialog(None)
        if res == JFileChooser.APPROVE_OPTION:
                self._destDir = self._destDirChooser.getSelectedFile()
                self._destDirLabel.setText(self._destDir.getAbsolutePath())
    
    #
    # Generate report into HTML checklist and logs to excel table
    #
    def generateReport(self, event):
        # Create a workbook and add a worksheet.
        file = str(self._destDir) + '/Burp-Logs.xlsx'
        self._stdout.println("Saving the file at " + str(file))
        workbook = xlsxwriter.Workbook(str(file))
        text_format  = workbook.add_format({'text_wrap': True})
        header_format = workbook.add_format({'bold' : True, 'underline' : True, 'bg_color' : 'red' })
                    
        httpTrafficSheet = workbook.add_worksheet('HTTP Traffic')
        passiveScanSheet = workbook.add_worksheet('Passive Scan')
        
        # Create the checklist
        baseTemplate = 'C:\\Users\\winston\\Desktop\\baseTemplate.html'
        newHTMLFile =  'C:\\Users\\winston\\Desktop\\Burp-Logs.html'        # DEBUG
        # newHTMLFile = str(self._destDir) + '/Burp-Logs.html'              # Actual Implementation
        
        shutil.copyfile(baseTemplate, newHTMLFile)  
        # load the checklist file
        with open(newHTMLFile) as inf:
            txt = inf.read()
            soup = BeautifulSoup(txt)
        
        # create the sheet headers
        httpTrafficSheet.write(0, 0 , "ID", header_format)
        httpTrafficSheet.write(0, 1 , "URL", header_format)
        httpTrafficSheet.write(0, 2 , "Logged Message", header_format)
        httpTrafficSheet.write(0, 3 , "Evidence", header_format)
        httpTrafficSheet.set_column(1,1,80)
        httpTrafficSheet.set_column(2,3,50)
        
        passiveScanSheet.write(0, 0 , "ID", header_format)
        passiveScanSheet.write(0, 1 , "URL", header_format)
        passiveScanSheet.write(0, 2 , "Serverity", header_format)
        passiveScanSheet.write(0, 3 , "Issues", header_format)
        passiveScanSheet.write(0, 4 , "Confident Level", header_format)  
        passiveScanSheet.set_column(1,1,80)
        passiveScanSheet.set_column(2,4,20)
        passiveScanSheet.set_column(3,3,40)
        
        # Write HTTP Traffic logs on sheet 1
        # Start from the second cell. Rows and columns are zero indexed.
        row = 1
        index = 1
        
        for log in self._log:
            height = log._logMsg.count("[+]")
            height = height * 20
            httpTrafficSheet.set_row(row, height)
            
            httpTrafficSheet.write(row, 0 , index)
            httpTrafficSheet.write(row, 1 , str(log._url))
            httpTrafficSheet.write(row, 2 , log._logMsg, text_format)
            httpTrafficSheet.write(row, 3 , log._evidence, text_format)
            index += 1
            row += 1 
            
            #
            # Write on checklist
            #
            
            # unencryptedChannelFlag (17)
            if log._unencryptedChannelFlag:
                original_string = soup.find("td", id="17e")
                original_string.string.replace_with(log._logMsg)
                original_string = soup.find("td", id="17f")
                original_string.string.replace_with(log._evidence)
            
            # serverInfoFlag (38)          
            if log._serverInfoFlag:
                original_string = soup.find("td", id="38e")
                original_string.string.replace_with(log._logMsg)
                original_string = soup.find("td", id="38f")
                original_string.string.replace_with(log._evidence)
                
            # base64Flag (46)          
            if log._base64Flag:
                original_string = soup.find("td", id="46e")
                original_string.string.replace_with(log._logMsg)
                original_string = soup.find("td", id="46f")
                original_string.string.replace_with(log._evidence)                
            # xcontentFlag (50)          
            if log._xcontentFlag:
                original_string = soup.find("td", id="50e")
                original_string.string.replace_with(log._logMsg)
                original_string = soup.find("td", id="50f")
                original_string.string.replace_with(log._evidence)                
            # cookieFlag (84)          
            if log._cookieFlag:
                original_string = soup.find("td", id="84e")
                original_string.string.replace_with(log._logMsg)
                original_string = soup.find("td", id="84f")
                original_string.string.replace_with(log._evidence)
                
        # Write scanner logs on sheet 2
        # Start from the second cell. Rows and columns are zero indexed.           
        row = 1 
        index = 1        
        for scan in self._scanLog:
            passiveScanSheet.write(row, 0, index)
            passiveScanSheet.write(row, 1, str(scan._url))
            passiveScanSheet.write(row, 2, scan._severity)
            passiveScanSheet.write(row, 3, scan._issueName)
            passiveScanSheet.write(row, 4, scan._confidence)
            index += 1
            row += 1 
            
            if scan._classification == "Web Directory Listing":
                original_string = soup.find("td", id="41e")
                original_string.string.replace_with("Automated Scan detected Web Directory Issues")
                original_string = soup.find("td", id="41f")
                original_string = soup.find("td", id="41f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                            
            elif scan._classification == "XSS":
                original_string = soup.find("td", id="54e")
                original_string.string.replace_with("Automated Scan detected XSS Issues")
                original_string = soup.find("td", id="54f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                            
            elif scan._classification == "SQL":   
                original_string = soup.find("td", id="57e")
                original_string.string.replace_with("Automated Scan detected SQL Issues")
                original_string = soup.find("td", id="57f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                            
            elif scan._classification == "LDAP":     
                original_string = soup.find("td", id="60e")
                original_string.string.replace_with("Automated Scan detected LDAP Issues")
                original_string = soup.find("td", id="60f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                        
            elif scan._classification == "XML/JSON/Flash/XPath/HTML/XFS Injection":
                original_string = soup.find("td", id="63e")
                original_string.string.replace_with("Automated Scan detected XML/JSON/Flash/XPath/HTML/XFS Injection Issues")
                original_string = soup.find("td", id="63f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                            
            elif scan._classification == "SSI":
                original_string = soup.find("td", id="67e")
                original_string.string.replace_with("Automated Scan detected SSI Issues")
                original_string = soup.find("td", id="67f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                            
            elif scan._classification == "IMAP/SMTP":
                original_string = soup.find("td", id="70e")
                original_string.string.replace_with("Automated Scan detected IMAP/SMTP Issues")
                original_string = soup.find("td", id="70f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                            
            elif scan._classification == "OS Command":
                original_string = soup.find("td", id="73e")
                original_string.string.replace_with("Automated Scan detected OS Command Issues")
                original_string = soup.find("td", id="74f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                            
            elif scan._classification == "Sensitive Source Code":
                original_string = soup.find("td", id="103e")
                original_string.string.replace_with("Automated Scan detected Sensitive Source Code Issues")
                original_string = soup.find("td", id="103f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
                        
            elif scan._classification == "Cacheable HTTPS response":
                original_string = soup.find("td", id="105e")
                original_string.string.replace_with("Automated Scan detected Cacheable HTTPS response Issues")
                original_string = soup.find("td", id="105f")
                currentString = original_string.string
                if currentString == "-":
                    original_string.string.replace_with("Issues detected: " + scan._issueName)
                else:
                    original_string.string.replace_with(currentString + ", " + scan._issueName)
            
        workbook.close()
        
        
        # save the file again
        with open(newHTMLFile, "w") as outf:
            outf.write(str(soup))
            self._stdout.println("Updated the file!")
        
        return
    
    #
    # logged existing scan issues
    #
    def getScanIssues(self, event):
        url = self.hostField.text
        if(len(url) == 0):
            return
        if url.find("://") == -1:
            host = "https://" + url
            host2 = "http://" + url
        try:
            scannedIssues = self._callbacks.getScanIssues(host)
            self._stdout.println("Size of scanned issues on this url: " + str(len(scannedIssues)))

            # Include to scope
            self._callbacks.includeInScope(URL(host))
            self._callbacks.includeInScope(URL(host2))
            self._stdout.println("Included in scope: " + host)
            self._stdout.println("Included in scope: " + host2)
            # Store Scan issue
            
            for issue in scannedIssues:
                if issue.getIssueName() not in self._repeatedIssue:
                    row = self._scanLog.size()
                    requestResponse = issue.getHttpMessages()
                    serverity = issue.getSeverity()
                    issueName = issue.getIssueName()
                    url = issue.getUrl()
                    confidence = issue.getConfidence()
                    scanMsg = issue.getIssueDetail()
                    
                    # Classification of Issues
                    if issueName in self._xssIssues:
                        classification = "XSS"
                    elif issueName in self._sqlIssues:
                        classification = "SQL"
                    elif issueName in self._ldapIssues:
                        classification = "LDAP"
                    elif issueName in self._ssiIssues:
                        classification = "SSI"
                    elif issueName in self._imapSmtpIssues:
                        classification = "IMAP/SMTP"
                    elif issueName in self._osCommandIssues:
                        classification = "OS Command"
                    elif issueName in self._sourceCodeIssues:
                        classification = "Sensitive Source Code"
                    elif issueName in self._webDirIssues:
                        classification = "Web Directory Listing"
                    elif issueName in self._xmlFlashHTMLIssues:
                        classification = "XML/JSON/Flash/XPath/HTML/XFS Injection"
                    elif issueName in self._cacheableIssues:
                        classification = "Cacheable HTTPS response"
                    else:
                        classification = "-"
                    if len(requestResponse) == 1 :
                        scan = ScanEntry(requestResponse[0], serverity, issueName, url, confidence, scanMsg, classification)
                    else:
                        scan = ScanEntry(None, serverity, issueName, url, confidence, scanMsg, classification)

                    self._scanModel.setValueAt(scan, row, row)
                    self._repeatedIssue.append(issue.getIssueName())
            #
            # register ourselves as IscannerListener
            self._callbacks.registerScannerListener(self)   
        
        except BaseException as e:
            print(e)
            return

    
    # implement IscannerListener
    def newScanIssue(self, issue):
        if issue.getIssueName() not in self._repeatedIssue:
            row = self._scanLog.size()
            requestResponse = issue.getHttpMessages()
            serverity = issue.getSeverity()
            issueName = issue.getIssueName()
            url = issue.getUrl()
            confidence = issue.getConfidence()
            scanMsg = issue.getIssueDetail()
            
            # Classification of Issues
            if issueName in self._xssIssues:
                classification = "XSS"
            elif issueName in self._sqlIssues:
                classification = "SQL"
            elif issueName in self._ldapIssues:
                classification = "LDAP"
            elif issueName in self._ssiIssues:
                classification = "SSI"
            elif issueName in self._imapSmtpIssues:
                classification = "IMAP/SMTP"
            elif issueName in self._osCommandIssues:
                classification = "OS Command"
            elif issueName in self._sourceCodeIssues:
                classification = "Sensitive Source Code"
            elif issueName in self._webDirIssues:
                classification = "Web Directory Listing"
            elif issueName in self._xmlFlashHTMLIssues:
                classification = "XML/JSON/Flash/XPath/HTML/XFS Injection"
            elif issueName in self._cacheableIssues:
                classification = "Cacheable HTTPS response"
            else:
                classification = "-"

            if len(requestResponse) == 1 :
                scan = ScanEntry(requestResponse[0], serverity, issueName, url, confidence, scanMsg, classification)
            else:
                scan = ScanEntry(None, serverity, issueName, url, confidence, scanMsg, classification)

            self._scanModel.setValueAt(scan, row, row)
            self._repeatedIssue.append(issue.getIssueName())
    
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
    # implement ITab
    #
    def getTabCaption(self):
        return "Development Scanner"
   
    def getUiComponent(self):
        return self._mainTab
    
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
    
    def resetLogMsg(self):
        self._row = self._log.size()
        self._logMsg = ""
        self._evidence = ""
        self._toLog = False
        self._partial_cookie_flag = False
        self._base64Flag = False
        self._xcontentFlag = False
        self._unencryptedChannelFlag = False
        self._cookieFlag = False
        self._serverInfoFlag = False
        
    def storeLog(self,message):
        log = LogEntry(self._callbacks.TOOL_PROXY, self._callbacks.saveBuffersToTempFiles(message.getMessageInfo()), self._helpers.analyzeRequest(message.getMessageInfo()).getUrl(), self._logMsg,self._evidence, self._unencryptedChannelFlag,self._base64Flag,self._xcontentFlag,self._cookieFlag, self._serverInfoFlag)
        self._logModel.setValueAt(log, self._row, self._row)
        self._stdout.println(log._logMsg)
        self.resetLogMsg()
        
    #
    # Log the HTTPMessage if falls into requirements
    #
    def logMessage(self, message):    
        self.resetLogMsg()
        requestInfo = self._helpers.analyzeRequest(message.messageInfo.getHttpService() , message.messageInfo.getRequest())
        responseInfo = self._helpers.analyzeResponse(message.messageInfo.getResponse())
        cookieInfo = responseInfo.getCookies()
        requestHeaderList = requestInfo.getHeaders()
        respondHeaderList = responseInfo.getHeaders()
        inner_sec_flag = False
        partial_cookie_flag = False
        partial_cookie_msg = ""
        
        # Capture Port 80 Request (17)
        if (message.getMessageInfo().getHttpService().getPort() == 80 and self._httpRequestFlag == False):
            self._logMsg += "[+] Send on 80 :" + message.getMessageInfo().getHttpService().getHost() + "\n"
            self._toLog = True
            self._httpRequestFlag = True
            
            if responseInfo.getStatusCode() < 300 and responseInfo.getStatusCode() >= 200:
                self._logMsg += "[+] Server Return 2xx Success Message from a HTTP Request detected, potential sensitive information being transmitted over non-SSL connections\n"
            elif ((responseInfo.getStatusCode() == 302) or (responseInfo.getStatusCode() == 301) or (responseInfo.getStatusCode() == 304) ) :
                self._logMsg += "[+] Server Return "+ str(responseInfo.getStatusCode()) +" Redirection Message from a HTTP Request detected\n"

            self._evidence += respondHeaderList[0] + "\n"
            self._evidence += respondHeaderList[1] + "\n"
            self._evidence += respondHeaderList[2] + "\n"
            self._evidence += respondHeaderList[3] + "\n"
            self._evidence += respondHeaderList[4] + "\n"
                
            if (self._toLog):
                self._unencryptedChannelFlag  = True
                self.storeLog(message)
               
        
        # Checking Response Header for server info leakage (38)
        for header in respondHeaderList: 
            tokens = header.split(":")
            
            # Capture information if there is a server response header
            if "server" in header.lower() and len(tokens[1]) != 1 and self._serverDetailFlag == False:
                self._logMsg += "[+] Potential Server Details:" + tokens[1] + "\n"
                self._evidence += header + "\n"
                self._serverDetailFlag = True
                self._toLog = True
            
            # Capture information if there is a server information leakage
            if "x-powered-by" in header.lower() and len(tokens[1]) != 1:
                self._logMsg += "[+] Web Server powered by :" + tokens[1] + "\n"
                self._toLog = True
                self._evidence += header + "\n"
        if (self._toLog):
            self._serverInfoFlag = True
            self.storeLog(message)
       
        # Checking Request Header for Base64 weak authentication request(46)
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
                self._logMsg += "[+] Basic Authentication request is being used, decoded found: " + decode + "\n"
                self._toLog = True
                self._basicAuthenticationFlag = True
                self._base64Flag = True
                self._evidence += header + "\n" 
                if (self._toLog):
                    self.storeLog(message)
                
        # Checking Response Header for X-Content (50)
        for header in respondHeaderList: 
            tokens = header.split(":")
        
            # Check for security headers that enforces security endpoint web browsers
            # Reference to: https://www.owasp.org/index.php/REST_Security_Cheat_Sheet
            #         
            if (self._secHeaderFlag == False):            
                if "x-content-type-options" == tokens[0].lower():
                    self._logMsg += "[+] X-Content-Type-Options header implemented\n"
                    inner_sec_flag = True
                    self._evidence += header + "\n"
                    
                if "x-frame-options" == tokens[0].lower():
                    self._logMsg += "[+] X-Frame-Options implemented\n" 
                    inner_sec_flag = True
                    self._evidence += header + "\n"
                if "x-xss-protection" == tokens[0].lower():
                    self._logMsg += "[+] X-xss-protection implemented\n" 
                    inner_sec_flag = True
                    self._evidence += header + "\n"
                if "content-type" == tokens[0].lower(): 
                    self._logMsg += "[+] Content-Type implemented\n"
                    inner_sec_flag = True
                    self._evidence += header + "\n"
        if inner_sec_flag:
            self._secHeaderFlag = True
            self._xcontentFlag = True
            self.storeLog(message)

        # Checking Cookie Flag(84)
        for header in respondHeaderList: 
            tokens = header.split(":")
           # Check for cookie flag return from server.
            if(self._cookieOverallFlag == False and "set-cookie" in header.lower()):
                if ("secure" in header.lower() and "httponly" in header.lower()):
                    self._logMsg += "[+] Secure and HTTPOnly cookie flags are implemented\n"
                    partial_cookie_flag = True
                    self._evidence = header
                    self._cookieOverallFlag  = True
                elif ("secure" in header.lower()):
                    partial_cookie_flag = True
                    self._logMsg = "Only Secure cookie flags is implemented\n"
                    self._evidence = header
                    self._cookieOverallFlag  = True
                elif ("httponly" in header.lower()):
                    partial_cookie_flag = True
                    self._logMsg = "Only HTTPOnly cookie flags is implemented\n"  
                    self._evidence = header
                    self._cookieOverallFlag  = True
                else:
                    self._logMsg += "[+] No cookie flags implemented\n"
                    self._evidence = header
                    self._cookieOverallFlag  = True
                self._cookieOverallFlag = True
                self._cookieFlag = True
                self.storeLog(message)
  
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

class logModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        try:
            return self._extender._log.size()
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
        logEntry= self._extender._log.get(rowIndex)
        if columnIndex == 0:
            return self._extender._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return  logEntry._url.toString()
        return ""
        
    def setValueAt(self, log, rowIndex, columnIndex):
        self._extender._log.add(log)
        self.fireTableRowsInserted(rowIndex, columnIndex)
 
class scanModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        try:
            return self._extender._scanLog.size()
        except:
            return 0

    def getColumnCount(self):
        return 6

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "ID"
        if columnIndex == 1:
            return "Severity"
        if columnIndex == 2:
            return "Issue Name"
        if columnIndex == 3:
            return "URL"
        if columnIndex == 4:
            return "Confidence"
        if columnIndex == 5:
            return "Classification"

        return ""

    def getValueAt(self, rowIndex, columnIndex):
        scanEntry= self._extender._scanLog.get(rowIndex)
        if columnIndex == 0:
            return rowIndex +1
        if columnIndex == 1:
            return  scanEntry._severity
        if columnIndex == 2:
            return  scanEntry._issueName
        if columnIndex == 3:
            return  scanEntry._url.toString()
        if columnIndex == 4:
            return  scanEntry._confidence
        if columnIndex == 5:
            return  scanEntry._classification
        return ""
        
    def setValueAt(self, scan, rowIndex, columnIndex):
        self._extender._scanLog.add(scan)
        self.fireTableRowsInserted(rowIndex, columnIndex)
        
#
# extend JTable to handle cell selection
#   
class Table(JTable):
    def __init__(self, extender1, extender2):
        self._extender = extender1
        self.setModel(extender2)
    
    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)    
        self._extender._logMsgViewer.setText(logEntry._logMsg)
        self._extender._evidenceViewer.setText(logEntry._evidence)
        self._extender._requestViewer2.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer2.setMessage(logEntry._requestResponse.getResponse(), False)
        JTable.changeSelection(self, row, col, toggle, extend)

class ScanTable(JTable):
    def __init__(self, extender1, extender2):
        self._extender = extender1
        self.setModel(extender2)
        
    def changeSelection(self, row, col, toggle, extend):
    
        # show the scan entry for the selected scan
        scanEntry = self._extender._scanLog.get(row)
        self._extender._scanMsgViewer.setText(scanEntry._scanMsg)
        if scanEntry._requestResponse is None:
            self._extender._requestViewer2.setMessage("", True)
            self._extender._responseViewer2.setMessage("", False)        
        else:
            self._extender._requestViewer2.setMessage(scanEntry._requestResponse.getRequest(), True)
            self._extender._responseViewer2.setMessage(scanEntry._requestResponse.getResponse(), False)
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#
class LogEntry:
    def __init__(self, tool, requestResponse, url,logMsg, evidence, unencryptedChannelFlag,base64Flag,xcontentFlag,cookieFlag, serverInfoFlag):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._logMsg = logMsg
        self._evidence = evidence
        self._unencryptedChannelFlag = unencryptedChannelFlag
        self._base64Flag = base64Flag
        self._xcontentFlag = xcontentFlag
        self._cookieFlag = cookieFlag
        self._serverInfoFlag  = serverInfoFlag 
#
# class to hold details of each scanner entry
#        
class ScanEntry:
    def __init__(self, requestResponse, severity, issueName, url, confidence, scanMsg, classification):
        self._requestResponse = requestResponse
        self._severity = severity
        self._issueName = issueName
        self._url = url
        self._confidence = confidence
        self._scanMsg = scanMsg
        self._classification = classification
               