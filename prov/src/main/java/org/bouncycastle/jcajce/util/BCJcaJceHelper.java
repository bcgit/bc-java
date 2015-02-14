package org.bouncycastle.jcajce.util;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A JCA/JCE helper that refers to the BC provider for all it's needs.
 */
public class BCJcaJceHelper
    extends ProviderJcaJceHelper
{
    private static Provider getBouncyCastleProvider()
    {
        if (Security.getProvider("BC") != null)
        {
            return Security.getProvider("BC");
        }
        else
        {
            return new BouncyCastleProvider();
        }
    }

    public BCJcaJceHelper()
    {
        super(getBouncyCastleProvider());
    }
}
