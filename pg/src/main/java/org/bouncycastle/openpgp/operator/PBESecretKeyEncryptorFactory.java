package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.PublicKeyPacket;

/**
 * Factory class for password-based secret key encryptors.
 * A concrete implementation of this class can not only choose the cryptographic backend (e.g. BC, JCA/JCE),
 * but also, whether to use AEAD (RFC9580) or classic CFB (RFC4880).
 */
public abstract class PBESecretKeyEncryptorFactory
{

    /**
     * Build a new {@link PBESecretKeyEncryptor} instance from the given passphrase and public key packet.
     *
     * @param passphrase passphrase
     * @param pubKeyPacket public-key packet of the key to protect (needed for AEAD)
     * @return key encryptor
     */
    public abstract PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket);
}
