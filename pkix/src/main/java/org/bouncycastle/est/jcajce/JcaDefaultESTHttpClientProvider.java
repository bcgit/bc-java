package org.bouncycastle.est.jcajce;

import java.util.Set;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.est.ESTClient;
import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTException;

public class JcaDefaultESTHttpClientProvider
    implements ESTClientProvider
{

    private final JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private final SocketFactoryCreator socketFactoryCreator;

    private final int timeout;
    private final ChannelBindingProvider bindingProvider;
    private final Set<String> cipherSuites;
    private final Long absoluteLimit;


    public JcaDefaultESTHttpClientProvider(
        JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer,
        SocketFactoryCreator socketFactoryCreator, int timeout,
        ChannelBindingProvider bindingProvider,
        Set<String> cipherSuites, Long absoluteLimit)
    {

        this.hostNameAuthorizer = hostNameAuthorizer;
        this.socketFactoryCreator = socketFactoryCreator;
        this.timeout = timeout;
        this.bindingProvider = bindingProvider;
        this.cipherSuites = cipherSuites;
        this.absoluteLimit = absoluteLimit;
    }

    public ESTClient makeClient()
        throws ESTException
    {
        try
        {
            SSLSocketFactory socketFactory = socketFactoryCreator.createFactory();
            return new DefaultESTClient(
                new DefaultESTClientSourceProvider(socketFactory, hostNameAuthorizer, timeout, bindingProvider, cipherSuites, absoluteLimit));
        }
        catch (Exception e)
        {
            throw new ESTException(e.getMessage(), e.getCause());
        }
    }


    public boolean isTrusted()
    {
        return socketFactoryCreator.isTrusted();
    }
}
