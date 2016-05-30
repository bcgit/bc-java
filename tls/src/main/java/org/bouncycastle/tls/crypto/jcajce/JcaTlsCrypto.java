package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;

import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;

public class JcaTlsCrypto implements TlsCrypto
{
    protected TlsContext context;

    public void init(TlsContext context)
    {
        this.context = context;
    }

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
}
