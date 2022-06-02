package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;

public class FalconParameters
    implements CipherParameters
{

    public static final FalconParameters falcon512 = new FalconParameters("falcon512", 9, 40, new SHAKEDigest(256));
    public static final FalconParameters falcon1024 = new FalconParameters("falcon1024", 10, 40, new SHAKEDigest(256));

    private final String name;
    private final int logn;
    private final int nounce_len;
    private final Xof digest;
    private final FalconEngine engine;

    public FalconParameters(String name, int logn, int nounce_len, Xof digest)
    {
        this.name = name;
        this.logn = logn;
        this.digest = digest;
        this.engine = new FalconEngine(logn);
        this.nounce_len = nounce_len;
    }

    public String getName()
    {
        return name;
    }

    public Xof getDigest()
    {
        return digest;
    }

    public FalconEngine getEngine()
    {
        return engine;
    }

    public int getLogn()
    {
        return logn;
    }

    public int getNounceLen()
    {
        return nounce_len;
    }
}
