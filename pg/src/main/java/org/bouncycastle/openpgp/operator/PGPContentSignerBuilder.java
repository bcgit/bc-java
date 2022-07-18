package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;

public interface PGPContentSignerBuilder
{
    PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey)
        throws PGPException;
}
