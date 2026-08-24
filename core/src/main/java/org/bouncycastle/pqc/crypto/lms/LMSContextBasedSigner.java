package org.bouncycastle.pqc.crypto.lms;

/**
 * @deprecated use {@link org.bouncycastle.crypto.signers.LMSContextBasedSigner} instead.
 */
@Deprecated
public interface LMSContextBasedSigner
{
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext context);

    long getUsagesRemaining();
}
