package org.bouncycastle.jsse.provider.gm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.crypto.TlsCertificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.SocketException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Empty session to prevent errors
 *
 * @since 2021-03-17 16:35:18
 */
public class GMSession implements SSLSession
{
    private boolean valid = true;

    private long created;
    private long updated;

    private Map<String, Object> contextValue;

    private GMSimpleSSLSocket gmScoket;

    private SecurityParameterProvider secParamProvider;

    private  CertificateFactory cf;

    public GMSession(GMSimpleSSLSocket scoket)
    {
        gmScoket = scoket;
        contextValue = new HashMap<String, Object>();
        renew(null);

        try
        {
           cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        }
        catch (java.security.cert.CertificateException e)
        {
            throw new RuntimeException(e);
        }
    }

    public void renew(SecurityParameterProvider secParamProvider)
    {
        final long now = System.currentTimeMillis();
        if (created == 0) {
            created = now;
        }
        updated = now;
        this.secParamProvider = secParamProvider;
    }

    public byte[] getId()
    {
        if (secParamProvider == null)
        {
            return new byte[0];
        }
        return secParamProvider.getSecurityParameters().getSessionID();
    }

    public SSLSessionContext getSessionContext()
    {
        return null;
    }

    public long getCreationTime()
    {
        return this.created;
    }

    public long getLastAccessedTime()
    {
        return this.updated;
    }

    public void invalidate()
    {
        valid = false;
    }

    public boolean isValid()
    {
        return valid;
    }

    public void putValue(String s, Object o)
    {
        this.contextValue.put(s, o);
    }

    public Object getValue(String s)
    {
        return this.contextValue.get(s);
    }

    public void removeValue(String s)
    {
        this.contextValue.remove(s);
    }

    public String[] getValueNames()
    {
        final Set<String> keySet = this.contextValue.keySet();
        final int len = keySet.size();
        String[] res = new String[len];
        int i = 0;
        for (String s : keySet)
        {
            res[i] = s;
            i++;
        }
        return res;
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException
    {
        if (secParamProvider == null)
        {
            return new Certificate[0];
        }
        final org.bouncycastle.tls.Certificate peerCertificate =
                secParamProvider.getSecurityParameters().getPeerCertificate();
        final TlsCertificate[] list = peerCertificate.getCertificateList();
        Certificate[] res = new Certificate[list.length];
        for (int i = 0; i < list.length; i++)
        {
            try
            {
                final byte[] encoded = list[i].getEncoded();
                res[i] = cf.generateCertificate(new ByteArrayInputStream(encoded));
            }
            catch (java.security.cert.CertificateException e)
            {
                throw new SSLPeerUnverifiedException("peer cert encoded error: " + e.getMessage());
            }
            catch (IOException e)
            {
                throw new SSLPeerUnverifiedException("peer cert encoded error: " + e.getMessage());
            }
        }
        return res;
    }

    public Certificate[] getLocalCertificates()
    {
        if (secParamProvider == null)
        {
            return new Certificate[0];
        }

        final org.bouncycastle.tls.Certificate localCertificate =
                secParamProvider.getSecurityParameters().getLocalCertificate();
        final TlsCertificate[] list = localCertificate.getCertificateList();
        Certificate[] res = new Certificate[list.length];
        for (int i = 0; i < list.length; i++)
        {
            try
            {

                final byte[] encoded = list[i].getEncoded();
                res[i] = cf.generateCertificate(new ByteArrayInputStream(encoded));
            }
            catch (java.security.cert.CertificateException e)
            {
                throw new RuntimeException("local cert encoded error: " + e.getMessage());
            }
            catch (IOException e)
            {
                throw new RuntimeException("local cert encoded error: " + e.getMessage());
            }
        }
        return res;
    }

    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
    {
        if (secParamProvider == null)
        {
            return new X509Certificate[0];
        }

        org.bouncycastle.tls.Certificate peerCert =
                secParamProvider.getSecurityParameters().getPeerCertificate();

        final TlsCertificate[] list = peerCert.getCertificateList();
        X509Certificate[] res = new X509Certificate[list.length];
        for (int i = 0; i < list.length; i++) {
            try
            {
                final byte[] encoded = list[i].getEncoded();
                res[i] = X509Certificate.getInstance(encoded);
            }
            catch (IOException e)
            {
                throw new SSLPeerUnverifiedException("peer cert encoded error: " + e.getMessage());
            }
            catch (CertificateException e)
            {
                throw new SSLPeerUnverifiedException("peer cert encoded error: " + e.getMessage());
            }

        }
        return res;
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException
    {
        final X509Certificate[] peerCertificateChain = this.getPeerCertificateChain();
        if (peerCertificateChain == null || peerCertificateChain.length == 0)
        {
            return null;
        }
        return peerCertificateChain[0].getSubjectDN();
    }

    public Principal getLocalPrincipal()
    {
        org.bouncycastle.tls.Certificate cert =
                secParamProvider.getSecurityParameters().getLocalCertificate();

        final TlsCertificate[] list = cert.getCertificateList();
        if (list.length == 0){
            return null;
        }
        final byte[] encoded;
        try {
            encoded = list[0].getEncoded();
            return X509Certificate.getInstance(encoded).getSubjectDN();
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        catch (CertificateException e)
        {
            throw new RuntimeException(e);
        }
    }

    public String getCipherSuite()
    {
        return "GMSSL_SM2_SM4_SM3";
    }

    public String getProtocol()
    {
        return "GMSSLv1.1";
    }

    public String getPeerHost()
    {
        return gmScoket.getRemoteSocketAddress().toString();
    }

    public int getPeerPort()
    {
        return gmScoket.getPort();
    }

    public int getPacketBufferSize()
    {
        try
        {
            return gmScoket.getSendBufferSize();
        }
        catch (SocketException e)
        {
            return 0;
        }
    }

    public int getApplicationBufferSize()
    {
        try
        {
            return gmScoket.getSendBufferSize();
        }
        catch (SocketException e)
        {
            return 0;
        }
    }
}
