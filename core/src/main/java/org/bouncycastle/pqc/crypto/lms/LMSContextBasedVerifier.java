package org.bouncycastle.pqc.crypto.lms;

public interface LMSContextBasedVerifier
{
    LMSContext generateLMSContext(byte[] signature);

    boolean verify(LMSContext context);
}
