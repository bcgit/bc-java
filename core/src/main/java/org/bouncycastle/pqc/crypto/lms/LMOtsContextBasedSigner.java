package org.bouncycastle.pqc.crypto.lms;

public interface LMOtsContextBasedSigner
{
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext context);
}
