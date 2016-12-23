package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.Signature;

class JcaUtils
{
    static boolean signatureAssumesDigestAlgorithmFromSize(Signature signature)
    {
        return signature.getProvider().getName().equalsIgnoreCase("SunMSCAPI");
    }
}
