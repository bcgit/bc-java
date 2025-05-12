package org.bouncycastle.tls.crypto;

import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

public class TlsKemConfig
{
    protected final KTSParameterSpec ktsParameterSpec;
    protected final int namedGroup;
    protected final boolean isServer;

    public TlsKemConfig(int namedGroup, boolean isServer)
    {
        this.namedGroup = namedGroup;
        this.isServer = isServer;
        this.ktsParameterSpec = new KTSParameterSpec.Builder("AES-KWP", 256).withNoKdf().build();
    }
    public TlsKemConfig(int namedGroup, boolean isServer, KTSParameterSpec ktsParameterSpec)
    {
        this.namedGroup = namedGroup;
        this.isServer = isServer;
        this.ktsParameterSpec = ktsParameterSpec;
    }

    public int getNamedGroup()
    {
        return namedGroup;
    }

    public boolean isServer()
    {
        return isServer;
    }

    public KTSParameterSpec getKtsParameterSpec()
    {
        return ktsParameterSpec;
    }
}
