package org.bouncycastle.crypto.signers;

import org.bouncycastle.crypto.signers.lms.LMSContext;

public interface LMSContextBasedVerifier
{
    LMSContext generateLMSContext(byte[] signature);

    boolean verify(LMSContext context);
}
