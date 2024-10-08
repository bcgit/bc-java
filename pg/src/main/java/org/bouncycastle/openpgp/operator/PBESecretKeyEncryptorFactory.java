package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.PublicKeyPacket;

public abstract class PBESecretKeyEncryptorFactory
{
    public abstract PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket);
}
