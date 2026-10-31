package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.kems.cmce.CMCEEngine;
import org.bouncycastle.util.Arrays;

/**
 * @deprecated Now believed unsafe to use - will be removed in a future release.
 */
@Deprecated
public class CMCEPublicKeyParameters
    extends CMCEKeyParameters
{
    final byte[] publicKey;

    public CMCEPublicKeyParameters(CMCEParameters params, byte[] publicKey)
    {
        super(false, params);

        if (publicKey.length != CMCEEngine.getInstance(params).getPublicKeySize())
        {
            throw new IllegalArgumentException("'publicKey' has invalid length");
        }

        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }
}
