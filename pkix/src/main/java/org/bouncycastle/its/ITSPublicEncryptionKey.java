package org.bouncycastle.its;

import org.bouncycastle.oer.its.SymmAlgorithm;

public class ITSPublicEncryptionKey
{
    public enum symmAlgorithm
    {
        aes128Ccm(SymmAlgorithm.aes128Ccm.intValueExact());

        private final int tagValue;

        symmAlgorithm(int tagValue)
        {
            this.tagValue = tagValue;
        }
    }
}
