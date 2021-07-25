package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BasicTlsPSKExternal
    implements TlsPSKExternal
{
    protected final byte[] identity;
    protected final TlsSecret key;
    protected final int prfAlgorithm; 

    public BasicTlsPSKExternal(byte[] identity, TlsSecret key)
    {
        this(identity, key, PRFAlgorithm.tls13_hkdf_sha256);
    }

    public BasicTlsPSKExternal(byte[] identity, TlsSecret key, int prfAlgorithm)
    {
        this.identity = Arrays.clone(identity);
        this.key = key;
        this.prfAlgorithm = prfAlgorithm;
    }

    public byte[] getIdentity()
    {
        return identity;
    }

    public TlsSecret getKey()
    {
        return key;
    }

    public int getPRFAlgorithm()
    {
        return prfAlgorithm;
    }
}
