package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsSRP6Server;

final class BcTlsSRP6Server
    implements TlsSRP6Server
{
    private final SRP6Server srp6Server;

    BcTlsSRP6Server(SRP6Server srp6Server)
    {
        this.srp6Server = srp6Server;
    }

    public BigInteger generateServerCredentials()
    {
        return srp6Server.generateServerCredentials();
    }

    public BigInteger calculateSecret(BigInteger clientA)
        throws IOException
    {
        try
        {
            return srp6Server.calculateSecret(clientA);
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }
}
