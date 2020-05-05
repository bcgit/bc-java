package org.bouncycastle.pqc.crypto.lms;

public interface LMOtsContextBasedVerifier
{
    LMSContext generateLMSContext(byte[] signature);

    boolean verify(LMSContext context);
}
