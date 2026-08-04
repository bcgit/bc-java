package org.bouncycastle.operator.jcajce;

import java.security.Key;
import java.security.Provider;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.GenericKey;

class OperatorUtils
{
    static Key getJceKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof Key)
        {
            return (Key)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new SecretKeySpec((byte[])key.getRepresentation(), "ENC");
        }

        throw new IllegalArgumentException("unknown generic key type");
    }

    static OperatorHelper createDefaultHelper()
    {
        return new OperatorHelper(new DefaultJcaJceHelper());
    }

    static OperatorHelper createProviderHelper(Provider provider)
    {
        return new OperatorHelper(new ProviderJcaJceHelper(provider));
    }

    static OperatorHelper createNamedHelper(String providerName)
    {
        return new OperatorHelper(new NamedJcaJceHelper(providerName));
    }
}
