package org.bouncycastle.its;

import org.bouncycastle.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;

public interface ETSIKeyWrapper
{
    EncryptedDataEncryptionKey wrap(byte[] secretKey);
}
