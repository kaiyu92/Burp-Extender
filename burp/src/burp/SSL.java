package burp;

public class SSL {
	
	//Config
	private boolean sensitiveInfo;
	private boolean insecureProtocol;
	private boolean implementationEnforcement;
	
	// Sub-Config of ImplementationEnforcement
	private boolean sslImplementSensitiveInformationOverNonSSLConn;
	private boolean sslImplementSSLEnforce;
	private boolean sslImplementSessionNonSSLRedirect;
	private boolean sslImplementHTTPSCheck;
	
	public SSL() {
		setSensitiveInfo(true);
		setInsecureProtocol(true);
		setImplementationEnforcement(true);
		
		setSslImplementSensitiveInformationOverNonSSLConn(true);
		setSslImplementSSLEnforce(true);
		setSslImplementSessionNonSSLRedirect(true);
		setSslImplementHTTPSCheck(true);
	}

	public boolean isSensitiveInfo() {
		return sensitiveInfo;
	}

	public void setSensitiveInfo(boolean sensitiveInfo) {
		this.sensitiveInfo = sensitiveInfo;
	}

	public boolean isInsecureProtocol() {
		return insecureProtocol;
	}

	public void setInsecureProtocol(boolean insecureProtocol) {
		this.insecureProtocol = insecureProtocol;
	}

	public boolean isImplementationEnforcement() {
		return implementationEnforcement;
	}

	public void setImplementationEnforcement(boolean implementationEnforcement) {
		this.implementationEnforcement = implementationEnforcement;
	}

	public boolean isSslImplementSensitiveInformationOverNonSSLConn() {
		return sslImplementSensitiveInformationOverNonSSLConn;
	}

	public void setSslImplementSensitiveInformationOverNonSSLConn(boolean sslImplementSensitiveInformationOverNonSSLConn) {
		this.sslImplementSensitiveInformationOverNonSSLConn = sslImplementSensitiveInformationOverNonSSLConn;
	}

	public boolean isSslImplementSSLEnforce() {
		return sslImplementSSLEnforce;
	}

	public void setSslImplementSSLEnforce(boolean sslImplementSSLEnforce) {
		this.sslImplementSSLEnforce = sslImplementSSLEnforce;
	}

	public boolean isSslImplementSessionNonSSLRedirect() {
		return sslImplementSessionNonSSLRedirect;
	}

	public void setSslImplementSessionNonSSLRedirect(boolean sslImplementSessionNonSSLRedirect) {
		this.sslImplementSessionNonSSLRedirect = sslImplementSessionNonSSLRedirect;
	}

	public boolean isSslImplementHTTPSCheck() {
		return sslImplementHTTPSCheck;
	}

	public void setSslImplementHTTPSCheck(boolean sslImplementHTTPSCheck) {
		this.sslImplementHTTPSCheck = sslImplementHTTPSCheck;
	}
	
	public void sslStartScan() {
		String host = "google.com";
		
		if(host.length() ==  0) {
			// log error, return
			// TODO: Log Error
			return;
		}
		else if (host.contains("://") == false) {
			// set to HTTPS
			host = "https://" + host;
		}
		else {

		}
	}
	

}
