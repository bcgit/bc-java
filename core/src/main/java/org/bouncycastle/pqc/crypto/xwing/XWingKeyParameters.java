package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class XWingKeyParameters
    extends AsymmetricKeyParameter
{
    XWingKeyParameters(
        boolean isPrivate)
    {
        super(isPrivate);
    }
}
