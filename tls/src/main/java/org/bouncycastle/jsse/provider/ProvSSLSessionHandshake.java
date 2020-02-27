package org.bouncycastle.jsse.provider;

import java.util.List;
import java.util.Vector;

import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

class ProvSSLSessionHandshake
    extends ProvSSLSessionBase
{
    protected final SecurityParameters securityParameters;
    protected final JsseSecurityParameters jsseSecurityParameters;

    ProvSSLSessionHandshake(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort,
        SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters)
    {
        super(sslSessionContext, peerHost, peerPort);

        this.securityParameters = securityParameters;
        this.jsseSecurityParameters = jsseSecurityParameters;
    }

    String getApplicationProtocol()
    {
        return JsseUtils.getApplicationProtocol(securityParameters);
    }

    @Override
    protected int getCipherSuiteTLS()
    {
        return securityParameters.getCipherSuite();
    }

    @Override
    protected byte[] getIDArray()
    {
        return securityParameters.getSessionID();
    }

    @Override
    protected JsseSecurityParameters getJsseSecurityParameters()
    {
        return jsseSecurityParameters;
    }

    @Override
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return null;
    }

    @Override
    protected org.bouncycastle.tls.Certificate getLocalCertificateTLS()
    {
        return securityParameters.getLocalCertificate();
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms()
    {
        return getSupportedSignatureAlgorithms(false);
//        return SignatureSchemeInfo.getJcaSignatureAlgorithms(jsseSecurityParameters.localSigSchemes);
    }

    @Override
    protected org.bouncycastle.tls.Certificate getPeerCertificateTLS()
    {
        return securityParameters.getPeerCertificate();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms()
    {
        return getSupportedSignatureAlgorithms(true);
//        return SignatureSchemeInfo.getJcaSignatureAlgorithms(jsseSecurityParameters.peerSigSchemesCert);
    }

    @Override
    protected ProtocolVersion getProtocolTLS()
    {
        return securityParameters.getNegotiatedVersion();
    }

    @Override
    public List<BCSNIServerName> getRequestedServerNames()
    {
        return JsseUtils.convertSNIServerNames(securityParameters.getClientServerNames());
    }

    private String[] getSupportedSignatureAlgorithms(boolean forPeer)
    {
        boolean isServer = (ConnectionEnd.server == securityParameters.getEntity());
        boolean forServer = isServer ^ forPeer;

        @SuppressWarnings("unchecked")
        Vector<SignatureAndHashAlgorithm> sigAlgs = forServer
            ? securityParameters.getClientSigAlgsCert()
            : securityParameters.getServerSigAlgs();

        return JsseUtils.getSignatureSchemeNames(sigAlgs);
    }
}
