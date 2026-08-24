package org.bouncycastle.pqc.crypto.lms;

/**
 * @deprecated use {@link org.bouncycastle.crypto.signers.LMSContextBasedVerifier} instead.
 */
@Deprecated
public interface LMSContextBasedVerifier
{
    LMSContext generateLMSContext(byte[] signature);

    boolean verify(LMSContext context);
}
