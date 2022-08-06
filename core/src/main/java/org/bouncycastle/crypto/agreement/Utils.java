package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.DHKeyParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, ECKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getCurve()), k);
    }

    static CryptoServiceProperties getDefaultProperties(String algorithm, DHKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, ConstraintUtils.bitsOfSecurityFor(k.getParameters().getP()), k);
    }
}
