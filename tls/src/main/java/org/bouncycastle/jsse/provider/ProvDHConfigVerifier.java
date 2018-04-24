package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.DefaultTlsDHConfigVerifier;
import org.bouncycastle.tls.crypto.TlsDHConfig;

class ProvDHConfigVerifier
    extends DefaultTlsDHConfigVerifier
{
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("org.bouncycastle.jsse.client.dh.minimumPrimeBits", 2048, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.client.dh.unrestrictedGroups", false);

    ProvDHConfigVerifier()
    {
        super(provMinimumPrimeBits);
    }

    @Override
    protected boolean checkGroup(TlsDHConfig dhConfig)
    {
        return provUnrestrictedGroups || super.checkGroup(dhConfig);
    }
}
