package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

public interface PGPContentVerifierBuilder
{
    PGPContentVerifier build(final PGPPublicKey publicKey)
        throws PGPException;
}
