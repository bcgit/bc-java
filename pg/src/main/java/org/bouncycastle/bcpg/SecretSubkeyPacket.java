package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * basic packet for a PGP secret key
 */
public class SecretSubkeyPacket
    extends SecretKeyPacket
{
    /**
     * Parse a secret subkey packet from an input stream.
     *
     * @param in input stream
     * @throws IOException
     */
    SecretSubkeyPacket(
        BCPGInputStream in)
        throws IOException
    {
        super(SECRET_SUBKEY, in);
    }

    /**
     * Create a secret subkey packet.
     * If the encryption algorithm is NOT {@link SymmetricKeyAlgorithmTags#NULL},
     * the {@link #USAGE_SHA1} will be used as S2K usage, otherwise the key will be
     * unencrypted ({@link #USAGE_NONE}).
     *
     * @param pubKeyPacket public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param s2k          s2k identifier
     * @param iv           optional iv for the encryption algorithm
     * @param secKeyData   secret key data
     */
    public SecretSubkeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        super(SECRET_SUBKEY, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData);
    }

    /**
     * Create a secret subkey packet.
     *
     * @param pubKeyPacket public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param s2kUsage     s2k usage
     * @param s2k          s2k identifier
     * @param iv           optional iv for the encryption algorithm
     * @param secKeyData   secret key data
     */
    public SecretSubkeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Create a secret subkey packet.
     *
     * @param pubKeyPacket  public subkey packet
     * @param encAlgorithm  encryption algorithm
     * @param aeadAlgorithm aead algorithm
     * @param s2kUsage      s2k usage
     * @param s2K           s2k identifier
     * @param iv            optional iv for the AEAD algorithm or encryption algorithm
     * @param secKeyData    secret key data
     */
    SecretSubkeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int aeadAlgorithm,
        int s2kUsage,
        S2K s2K,
        byte[] iv,
        byte[] secKeyData)
    {
        super(SECRET_SUBKEY, pubKeyPacket, encAlgorithm, aeadAlgorithm, s2kUsage, s2K, iv, secKeyData);
    }
}
