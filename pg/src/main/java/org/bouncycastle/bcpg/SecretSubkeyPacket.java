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
     * @param in input stream
     * @throws IOException
     */
    SecretSubkeyPacket(
        BCPGInputStream    in)
        throws IOException
    { 
        super(in);
    }
    
    /**
     * Create a secret subkey packet.
     * If the encryption algorithm is NOT {@link SymmetricKeyAlgorithmTags#NULL},
     * the {@link #USAGE_SHA1} will be used as S2K usage, otherwise the key will be
     * unencrypted ({@link #USAGE_NONE}).
     *
     * @param pubKeyPacket public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param s2k s2k identifier
     * @param iv optional iv for the encryption algorithm
     * @param secKeyData secret key data
     */
    public SecretSubkeyPacket(
        PublicKeyPacket  pubKeyPacket,
        int              encAlgorithm,
        S2K              s2k,
        byte[]           iv,
        byte[]           secKeyData)
    {
        super(pubKeyPacket, encAlgorithm, s2k, iv, secKeyData);
    }

    /**
     * Create a secret subkey packet.
     * @param pubKeyPacket public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param s2kUsage s2k usage
     * @param s2k s2k identifier
     * @param iv optional iv for the encryption algorithm
     * @param secKeyData secret key data
     */
    public SecretSubkeyPacket(
        PublicKeyPacket  pubKeyPacket,
        int              encAlgorithm,
        int              s2kUsage,
        S2K              s2k,
        byte[]           iv,
        byte[]           secKeyData)
    {
        super(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Create a secret subkey packet.
     * @param pubKeyPacket public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param aeadAlgorithm aead algorithm
     * @param s2kUsage s2k usage
     * @param s2K s2k identifier
     * @param iv optional iv for the AEAD algorithm or encryption algorithm
     * @param secKeyData secret key data
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
        super(pubKeyPacket, encAlgorithm, aeadAlgorithm,s2kUsage, s2K, iv, secKeyData);
    }

    /**
     * Create a version 4 secret subkey packet.
     *
     * @param pubKeyPacket version 4 public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param s2kUsage s2k usage
     * @param s2k s2k identifier
     * @param iv optional iv for the encryption algorithm
     * @param secKeyData secret key data
     * @return secret subkey packet
     */
    public static SecretSubkeyPacket createV4SecretSubkey(
            PublicKeyPacket pubKeyPacket,
            int encAlgorithm,
            int s2kUsage,
            S2K s2k,
            byte[] iv,
            byte[] secKeyData)
    {
        if (pubKeyPacket.getVersion() != SecretKeyPacket.VERSION_4)
        {
            throw new IllegalArgumentException("Pubkey version mismatch. Expected 4, got " + pubKeyPacket.getVersion());
        }
        return new SecretSubkeyPacket(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Create a v6 secret subkey packet.
     * For AEAD encryption use {@link #createAeadEncryptedV6SecretSubkey(PublicSubkeyPacket, int, int, byte[], S2K, byte[])} instead.
     *
     * @param pubKeyPacket public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param s2kUsage s2k usage
     * @param s2k s2k identifier
     * @param iv optional iv for the symmetric algorithm
     * @param secKeyData secret key data
     * @return secret key packet
     */
    public static SecretKeyPacket createV6SecretSubkey(
            PublicKeyPacket pubKeyPacket,
            int encAlgorithm,
            int s2kUsage,
            S2K s2k,
            byte[] iv,
            byte[] secKeyData)
    {
        if (pubKeyPacket.getVersion() != VERSION_6)
        {
            throw new IllegalArgumentException("Pubkey version mismatch. Expected 6, got " + pubKeyPacket.getVersion());
        }
        if (s2kUsage == USAGE_AEAD)
        {
            throw new IllegalArgumentException("Use createAeadEncryptedV6SecretKey() instead.");
        }
        return new SecretSubkeyPacket(pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Create an AEAD encrypted v6 secret subkey packet.
     * @param pubKeyPacket public subkey packet
     * @param encAlgorithm encryption algorithm
     * @param aeadAlgorithm aead algorithm
     * @param aeadNonce nonce for the AEAD algorithm
     * @param s2k s2k identifier
     * @param secKeyData encrypted secret key data with appended AEAD auth tag
     * @return secret key packet
     */
    public static SecretKeyPacket createAeadEncryptedV6SecretSubkey(
            PublicSubkeyPacket pubKeyPacket,
            int encAlgorithm,
            int aeadAlgorithm,
            byte[] aeadNonce,
            S2K s2k,
            byte[] secKeyData)
    {
        if (pubKeyPacket.getVersion() != VERSION_6) {
            throw new IllegalArgumentException("Pubkey version mismatch. Expected 6, got " + pubKeyPacket.getVersion());
        }
        return new SecretSubkeyPacket(pubKeyPacket, encAlgorithm, aeadAlgorithm, USAGE_AEAD, s2k, aeadNonce, secKeyData);
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(SECRET_SUBKEY, getEncodedContents());
    }
}
