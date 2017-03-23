package org.bouncycastle.est.jcajce;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.est.ESTClientSourceProvider;
import org.bouncycastle.est.Source;
import org.bouncycastle.util.Strings;

class DefaultESTClientSourceProvider
    implements ESTClientSourceProvider
{

    private final SSLSocketFactory sslSocketFactory;
    private final JsseHostnameAuthorizer hostNameAuthorizer;
    private final int timeout;
    private final ChannelBindingProvider bindingProvider;
    private final Set<String> cipherSuites;
    private final Long absoluteLimit;


    public DefaultESTClientSourceProvider(
        SSLSocketFactory socketFactory,
        JsseHostnameAuthorizer hostNameAuthorizer,
        int timeout, ChannelBindingProvider bindingProvider,
        Set<String> cipherSuites, Long absoluteLimit)
        throws GeneralSecurityException
    {
        this.sslSocketFactory = socketFactory;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.timeout = timeout;
        this.bindingProvider = bindingProvider;
        this.cipherSuites = cipherSuites;
        this.absoluteLimit = absoluteLimit;
    }


    public Source makeSource(String host, int port)
        throws IOException
    {
        SSLSocket sock = (SSLSocket)sslSocketFactory.createSocket(host, port);
        sock.setSoTimeout(timeout);


        if (cipherSuites != null && !cipherSuites.isEmpty())
        {
            sock.setEnabledCipherSuites(cipherSuites.toArray(new String[cipherSuites.size()]));
        }

        sock.startHandshake();

        if (hostNameAuthorizer != null)
        {
            if (!hostNameAuthorizer.verified(host, sock.getSession()))
            {
                throw new IOException("Host name could not be verified.");
            }
        }

        {
            String t = Strings.toLowerCase(sock.getSession().getCipherSuite());
            if (t.contains("_des_") || t.contains("_des40_") || t.contains("_3des_"))
            {
                throw new IOException("EST clients must not use DES ciphers");
            }
        }

        // check for use of null cipher and fail.
        if (Strings.toLowerCase(sock.getSession().getCipherSuite()).contains("null"))
        {
            throw new IOException("EST clients must not use NULL ciphers");
        }

        // check for use of anon cipher and fail.
        if (Strings.toLowerCase(sock.getSession().getCipherSuite()).contains("anon"))
        {
            throw new IOException("EST clients must not use anon ciphers");
        }

        // check for use of anon cipher and fail.
        if (Strings.toLowerCase(sock.getSession().getCipherSuite()).contains("export"))
        {
            throw new IOException("EST clients must not use export ciphers");
        }

        if (sock.getSession().getProtocol().equalsIgnoreCase("tlsv1"))
        {
            try
            {
                sock.close();
            }
            catch (Exception ex)
            {
                // Deliberately ignored.
            }
            throw new IOException("EST clients must not use TLSv1");
        }


        if (hostNameAuthorizer != null && !hostNameAuthorizer.verified(host, sock.getSession()))
        {
            throw new IOException("Hostname was not verified: " + host);
        }
        return new LimitedSSLSocketSource(sock, bindingProvider, absoluteLimit);
    }
}
