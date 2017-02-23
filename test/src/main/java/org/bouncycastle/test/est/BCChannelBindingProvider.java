package org.bouncycastle.test.est;

import java.net.Socket;

import org.bouncycastle.est.jcajce.ChannelBindingProvider;
import org.bouncycastle.jsse.BcSSLConnection;
import org.bouncycastle.jsse.BcSSLSocket;

/**
 * BouncyCastle specific channel binding provider.
 * Access to channel bindings like tls-unique have not been standardised in JSSE.
 * So provider specific implementations must be built.
 */
public class BCChannelBindingProvider
    implements ChannelBindingProvider
{
    public boolean canAccessChannelBinding(Socket sock)
    {
        return sock instanceof BcSSLSocket;
    }

    public byte[] getChannelBinding(Socket sock, String binding)
    {
        BcSSLConnection bcon = ((BcSSLSocket)sock).getConnection();
        if (bcon != null)
        {
            return bcon.getChannelBinding(binding);
        }
        return null;
    }
}
