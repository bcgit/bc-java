package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public interface PGPContentVerifierBuilderProvider
{
    public PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
        throws PGPException;
}
