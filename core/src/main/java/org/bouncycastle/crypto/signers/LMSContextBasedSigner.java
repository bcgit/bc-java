package org.bouncycastle.crypto.signers;

import org.bouncycastle.crypto.signers.lms.LMSContext;

public interface LMSContextBasedSigner
{
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext context);

    long getUsagesRemaining();
}
