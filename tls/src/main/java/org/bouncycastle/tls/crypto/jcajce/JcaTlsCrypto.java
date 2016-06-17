package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;

import org.bouncycastle.tls.crypto.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsSecret;

public class JcaTlsCrypto extends AbstractTlsCrypto
{
    public byte[] calculateDigest(short hashAlgorithm, byte[] buf, int off, int len) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsCertificate createCertificate(byte[] encoding)
    {
        throw new UnsupportedOperationException();
    }
    
    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig)
    {
        throw new UnsupportedOperationException();
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        throw new UnsupportedOperationException();
    }

    public TlsSecret createSecret(byte[] data)
    {
        throw new UnsupportedOperationException();
    }
}
