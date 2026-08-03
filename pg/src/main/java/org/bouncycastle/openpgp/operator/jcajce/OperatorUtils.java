package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

class OperatorUtils
{
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
