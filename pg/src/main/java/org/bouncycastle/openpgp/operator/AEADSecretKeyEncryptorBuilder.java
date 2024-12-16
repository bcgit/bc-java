package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.PublicKeyPacket;

/**
 * Implementation provider for AEAD-based {@link PBESecretKeyEncryptor PBESecretKeyEncryptors}.
 */
public interface AEADSecretKeyEncryptorBuilder
{
    /**
     * Build a new {@link PBESecretKeyEncryptor} using the given passphrase.
     * Note: As the AEAD protection mechanism includes the public key packet of the key into the calculation,
     * if the key you want to protect is supposed to be a subkey, you need to convert it to one <b>before</b>
     * calling this method. See {@link org.bouncycastle.openpgp.PGPKeyPair#asSubkey(KeyFingerPrintCalculator)}.
     *
     * @param passphrase passphrase
     * @param pubKey public primary or subkey packet
     * @return encryptor using AEAD
     */
    PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKey);
}
