package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.Security;

class JcaUtils
{
    static boolean isSunMSCAPIProviderActive()
    {
        return null != Security.getProvider("SunMSCAPI");
    }
}
