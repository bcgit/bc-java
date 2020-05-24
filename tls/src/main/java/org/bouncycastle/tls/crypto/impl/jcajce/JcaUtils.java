package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.util.Strings;

class JcaUtils
{
    static String getJcaAlgorithmName(SignatureAndHashAlgorithm algorithm)
    {
        return (HashAlgorithm.getName(algorithm.getHash()) + "WITH"
            + Strings.toUpperCase(SignatureAlgorithm.getName(algorithm.getSignature())));
    }

    static boolean isSunMSCAPIProviderActive()
    {
        return null != Security.getProvider("SunMSCAPI");
    }

    static boolean isSunMSCAPIProvider(Provider provider)
    {
        return null != provider && isSunMSCAPIProviderName(provider.getName());
    }

    static boolean isSunMSCAPIProviderName(String providerName)
    {
        return "SunMSCAPI".equals(providerName);
    }
}
