package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.DefaultTlsDHGroupVerifier;
import org.bouncycastle.tls.crypto.DHGroup;

class ProvDHGroupVerifier
    extends DefaultTlsDHGroupVerifier
{
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("org.bouncycastle.jsse.client.dh.minimumPrimeBits", 2048, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.client.dh.unrestrictedGroups", false);

    ProvDHGroupVerifier()
    {
        super(provMinimumPrimeBits);
    }

    @Override
    protected boolean checkGroup(DHGroup dhGroup)
    {
        return provUnrestrictedGroups || super.checkGroup(dhGroup);
    }
}
