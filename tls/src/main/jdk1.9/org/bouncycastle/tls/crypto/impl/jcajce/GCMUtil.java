package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.GCMParameterSpec;

class GCMUtil
{
    static AlgorithmParameterSpec createGCMParameterSpec(final int tLen, final byte[] src)
        throws Exception
    {
        return new GCMParameterSpec(tLen, src);
    }

    static boolean isGCMParameterSpecAvailable()
    {
        return true;
    }
}
