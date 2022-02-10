package org.bouncycastle.its.operator;

import java.security.GeneralSecurityException;

import org.bouncycastle.its.ETSIRecipientInfo;

public interface ETSIDataDecryptor
{


    byte[] decrypt(byte[] wrappedKey, byte[] content, byte[] nonce);
}
