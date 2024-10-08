package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.PublicKeyPacket;

public interface AEADSecretKeyEncryptorBuilder
{
    PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKey);
}
