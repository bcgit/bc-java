package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Encodable;

public abstract class HSSKeyParameters
    extends AsymmetricKeyParameter
    implements Encodable
{
    protected HSSKeyParameters(boolean isPrivateKey)
    {
        super(isPrivateKey);
    }

    abstract public byte[] getEncoded()
        throws IOException;
}
