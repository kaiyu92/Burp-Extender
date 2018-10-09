package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.PrintWriter;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class BurpExtender implements IBurpExtender,ITab,ActionListener, IContextMenuFactory, IExtensionStateListener
{
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	//configuration fields
	private String reportFormat;
	private boolean inscopeOnly;
	private boolean mergeHttps; //merge http:80 and https:443 into one report
	private boolean mergeAll; //merge all protocols and ports into 1 report
	private File destDir;
	private boolean fileDate; //append generation date to filename in format MMDDYYYY	
	private static final String[] dateFormats = {"MMddyyyy","ddMMyyyy","yyyyMMdd","MMddyy","ddMMyy","yyMMdd"};

	//UI fields
	private JPanel mainPanel;
    private JEditorPane pluginConsoleTextArea;
	
    private PrintWriter stdout;
    private PrintWriter stderr;
	
	public void registerExtenderCallbacks (IBurpExtenderCallbacks cb)
	{
		// Reference to callback object
		this.callbacks = cb;
		
		// Get an extension helpers object
		this.helpers = callbacks.getHelpers();
		
		// Extension name
		this.callbacks.setExtensionName("GovTech Test v0.1");	
		
        //register to produce options for the context menu
        callbacks.registerContextMenuFactory(this);
        // register to execute actions on unload
        callbacks.registerExtensionStateListener(this);
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true); 
        
        SwingUtilities.invokeLater(new Runnable()  {

			@Override
			public void run() {
				// TODO Auto-generated method stub
				mainPanel = new JPanel();
            	mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

            	// **** Left panel (tabbed plus console)            	
            	JSplitPane consoleTabbedSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); 
            	
            	// Tab Panel
            	final JTabbedPane tabbedPanel = new JTabbedPane();
            	tabbedPanel.addChangeListener(new ChangeListener() {
                    public void stateChanged(ChangeEvent e) {
                       
                        SwingUtilities.invokeLater(new Runnable() {
            				
            	            @Override
            	            public void run() {
            	            	
            	            	showHideButtons(tabbedPanel.getSelectedIndex());
            					
            	            }
            			});	
                        
                    }
                });
            	
            	// ****** TABS ******************
            	
            	// ****** SSL PANEL
            	JPanel sslPanel = new JPanel();
            	sslPanel.setLayout(new BoxLayout(sslPanel, BoxLayout.Y_AXIS));
            	
	            	JPanel sensitiveInfoPanel = new JPanel();
	            	sensitiveInfoPanel.setLayout(new BoxLayout(sensitiveInfoPanel, BoxLayout.X_AXIS));
	            	sensitiveInfoPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
	            	JLabel sensitiveInfo = new JLabel("Sensitive Information sent via insecure communication channels");
	            	JCheckBox sslSensitiveInfoCheck = new JCheckBox((String) null,true);
	            	sensitiveInfoPanel.add(sensitiveInfo);
	            	sensitiveInfoPanel.add(sslSensitiveInfoCheck);
	
	            	JPanel insecureProtocolPanel = new JPanel();
	            	insecureProtocolPanel.setLayout(new BoxLayout(insecureProtocolPanel, BoxLayout.X_AXIS));
	            	insecureProtocolPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
	            	JLabel insecureProtocol = new JLabel("Insecure SSL protocol's Version");
	            	JCheckBox sslInsecureProtocolCheck = new JCheckBox((String) null,true);
	            	insecureProtocolPanel.add(insecureProtocol);
	            	insecureProtocolPanel.add(sslInsecureProtocolCheck);
	            	
	            	JPanel implementEnforcePanel = new JPanel();
	            	implementEnforcePanel.setLayout(new BoxLayout(implementEnforcePanel, BoxLayout.X_AXIS));
	            	implementEnforcePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
	            	JLabel implementEnforce = new JLabel("Implementation and enforcement of SSL Communication");
	            	JCheckBox sslImplementSensitiveInformationOverNonSSLConnCheck = new JCheckBox("Sensitive Info thru Non-SSL Connection", true);
	            	JCheckBox sslImplementSSLEnforceCheck = new JCheckBox("SSL enforced", false);
	            	JCheckBox sslImplementSessionNonSSLRedirect = new JCheckBox("Session created by Non-SSL redirected", false);
	            	JCheckBox sslImplementHTTPSCheck = new JCheckBox("HTTP & HTTPS contents on same page", false);
	        		JPanel sslImplementCheckPanel = new JPanel();
	        		sslImplementCheckPanel.setLayout(new BoxLayout(sslImplementCheckPanel, BoxLayout.Y_AXIS));
	        		sslImplementCheckPanel.add(sslImplementSensitiveInformationOverNonSSLConnCheck);
	        		sslImplementCheckPanel.add(sslImplementSSLEnforceCheck);
	        		sslImplementCheckPanel.add(sslImplementSessionNonSSLRedirect);
	        		sslImplementCheckPanel.add(sslImplementHTTPSCheck);
	            	implementEnforcePanel.add(implementEnforce);
	            	implementEnforcePanel.add(sslImplementCheckPanel);
	            	
	            	JButton SSLScanButton = new JButton("Start Scan");
	            	SSLScanButton.setActionCommand("sslScan");
	            	SSLScanButton.addActionListener(BurpExtender.this);
	            	
	            	sslPanel.add(sensitiveInfoPanel);
	            	sslPanel.add(insecureProtocolPanel);
	            	sslPanel.add(implementEnforcePanel);
	            	sslPanel.add(SSLScanButton);
            	
            	// ****** WEB SERVER PANEL
            	JPanel executeMethodPanel = new JPanel();
                executeMethodPanel.setLayout(new BoxLayout(executeMethodPanel, BoxLayout.Y_AXIS));
                
            	// ****** INPUT VALIDATION PANEL
                JPanel inputValidationpanel = new JPanel();
                inputValidationpanel.setLayout(new BoxLayout(inputValidationpanel, BoxLayout.Y_AXIS));
                
            	// ****** SESSION MANAGEMENT PANEL
                JPanel sessMgtPanel = new JPanel();
                sessMgtPanel.setLayout(new BoxLayout(sessMgtPanel, BoxLayout.Y_AXIS));
                
            	// ****** REPORT GENERATOR PANEL
                JPanel reportPanel = new JPanel();
                reportPanel.setLayout(new BoxLayout(reportPanel, BoxLayout.Y_AXIS));
                
             	tabbedPanel.add("SSL",sslPanel);
            	tabbedPanel.add("Web Server",executeMethodPanel); 
            	tabbedPanel.add("Input Validation",inputValidationpanel);
            	tabbedPanel.add("Session Management",sessMgtPanel);            	
            	tabbedPanel.add("Report Generator",reportPanel);
            	
            	// ******* CONSOLE *********
            	// *** CONSOLE            	
            	pluginConsoleTextArea = new JEditorPane("text/html", "<font color=\"green\"><b>*** GovTech console ***</b></font><br/><br/>");
                JScrollPane scrollPluginConsoleTextArea = new JScrollPane(pluginConsoleTextArea);
                scrollPluginConsoleTextArea.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                pluginConsoleTextArea.setEditable(false);
                
                consoleTabbedSplitPane.setTopComponent(tabbedPanel);
                consoleTabbedSplitPane.setBottomComponent(scrollPluginConsoleTextArea);
                consoleTabbedSplitPane.setResizeWeight(.7d);
            	

                mainPanel.add(consoleTabbedSplitPane);
                callbacks.customizeUiComponent(mainPanel);
                callbacks.addSuiteTab(BurpExtender.this);
			}
        	
        });
        
		
	}
	
	private void showHideButtons(int selectedIndex) {
		// TODO Auto-generated method stub
		
	}
	

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {		
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		String command = event.getActionCommand();

		if (command.equals("sslScan")) {
			SwingUtilities.invokeLater(new Runnable() {
				
				@Override
	            public void run() {
					SSL ssl = new SSL();
					ssl.sslStartScan();
				}
			});
		}
	}

	@Override
	public String getTabCaption() {
		return "GovTech Test v0.1";
	}

	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void extensionUnloaded() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return mainPanel;
	}

}