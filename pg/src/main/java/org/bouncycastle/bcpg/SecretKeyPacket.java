package org.bouncycastle.bcpg;

import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * basic packet for a PGP secret key
 */
public class SecretKeyPacket
    extends ContainedPacket
    implements PublicKeyAlgorithmTags
{
    public static final int VERSION_3 = 3;
    public static final int VERSION_4 = 4;
    public static final int VERSION_6 = 6;

    public static final int USAGE_NONE = 0x00;
    public static final int USAGE_CHECKSUM = 0xff;
    public static final int USAGE_SHA1 = 0xfe;
    public static final int USAGE_AEAD = 0xfd;

    private PublicKeyPacket pubKeyPacket;
    private byte[] secKeyData;
    private int s2kUsage;
    private int encAlgorithm;
    private int aeadAlgorithm;
    private S2K s2k;
    private byte[] iv;

    /**
     * Parse a SecretKeyPacket from an input stream.
     *
     * @param in input stream
     * @throws IOException
     */
    SecretKeyPacket(
        BCPGInputStream in)
        throws IOException
    {
        if (this instanceof SecretSubkeyPacket)
        {
            pubKeyPacket = new PublicSubkeyPacket(in);
        }
        else
        {
            pubKeyPacket = new PublicKeyPacket(in);
        }

        int version = pubKeyPacket.getVersion();
        s2kUsage = in.read();

        if (version == 6 && s2kUsage != USAGE_NONE) {
            // TODO: Use length to parse unknown parameters
            int conditionalParameterLength = in.read();
        }

        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD)
        {
            encAlgorithm = in.read();
        }
        else
        {
            encAlgorithm = s2kUsage;
        }
        if (s2kUsage == USAGE_AEAD)
        {
            aeadAlgorithm = in.read();
        }
        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD) {
            if (version == VERSION_6) {
                // TODO: Use length to parse unknown S2Ks
                int s2kLen = in.read();
            }
            s2k = new S2K(in);
        }
        if (s2kUsage == USAGE_AEAD) {
            iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
            Streams.readFully(in, iv);
        }
        boolean isGNUDummyNoPrivateKey = s2k != null &&
                s2k.getType() == S2K.GNU_DUMMY_S2K &&
                s2k.getProtectionMode() == S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY;
        if (!(isGNUDummyNoPrivateKey))
        {
            if (s2kUsage != 0 && iv == null)
            {
                if (encAlgorithm < 7)
                {
                    iv = new byte[8];
                }
                else
                {
                    iv = new byte[16];
                }
                in.readFully(iv, 0, iv.length);
            }
        }

        this.secKeyData = in.readAll();
    }

    /**
     * Create a secret key packet.
     * If the encryption algorithm is not {@link SymmetricKeyAlgorithmTags#NULL},
     * then {@link #USAGE_SHA1} will be used as S2K usage, otherwise the key will be
     * unencrypted ({@link #USAGE_NONE}).
     *
     * @param pubKeyPacket public key packet
     * @param encAlgorithm encryption algorithm
     * @param s2k s2k identifier
     * @param iv optional iv for the encryption algorithm
     * @param secKeyData secret key data
     */
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(
                pubKeyPacket,
                encAlgorithm,
                (encAlgorithm != SymmetricKeyAlgorithmTags.NULL ? USAGE_SHA1 : USAGE_NONE),
                s2k,
                iv,
                secKeyData);
    }

    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData);
    }

    SecretKeyPacket(
            PublicKeyPacket pubKeyPacket,
            int encAlgorithm,
            int aeadAlgorithm,
            int s2kUsage,
            S2K s2k,
            byte[] iv,
            byte[] secKeyData)
    {
        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;
        this.aeadAlgorithm = aeadAlgorithm;
        this.s2kUsage = s2kUsage;
        this.s2k = s2k;
        this.iv = iv;
        this.secKeyData = secKeyData;

        if (s2k != null && s2k.getType() == S2K.ARGON_2 && s2kUsage != USAGE_AEAD) {
            throw new IllegalArgumentException("Argon2 is only used with AEAD (S2K usage octet 253)");
        }

        if (pubKeyPacket.getVersion() == VERSION_6) {
            if (s2kUsage == USAGE_CHECKSUM) {
                throw new IllegalArgumentException("Version 6 keys MUST NOT use S2K usage USAGE_CHECKSUM");
            }
        }
    }

    /**
     * Create a v4 secret key packet.
     *
     * @param pubKeyPacket public key packet
     * @param encAlgorithm encryption algorithm
     * @param s2kUsage s2k usage
     * @param s2k s2k identifier
     * @param iv optional iv for the encryption algorithm
     * @param secKeyData secret key data
     * @return secret key packet
     */
    public static SecretKeyPacket createV4SecretKey(PublicKeyPacket pubKeyPacket,
                                                    int encAlgorithm,
                                                    int s2kUsage,
                                                    S2K s2k,
                                                    byte[] iv,
                                                    byte[] secKeyData)
    {
        if (pubKeyPacket.getVersion() != VERSION_4) {
            throw new IllegalArgumentException("Pubkey version mismatch. Expected 4, got " + pubKeyPacket.getVersion());
        }
        return new SecretKeyPacket(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Create a v6 secret key packet.
     * For AEAD encryption use {@link #createAeadEncryptedSecretKey(PublicKeyPacket, int, int, byte[], S2K, byte[])} instead.
     *
     * @param pubKeyPacket public key packet
     * @param encAlgorithm encryption algorithm
     * @param s2kUsage s2k usage
     * @param s2k s2k identifier
     * @param iv optional iv for the symmetric algorithm
     * @param secKeyData secret key data
     * @return secret key packet
     */
    public static SecretKeyPacket createV6SecretKey(
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
        return new SecretKeyPacket(pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData);
    }

    /**
     * Create an AEAD encrypted secret key packet.
     *
     * @param pubKeyPacket public key packet
     * @param encAlgorithm encryption algorithm
     * @param aeadAlgorithm aead algorithm
     * @param aeadNonce nonce for the AEAD algorithm
     * @param s2k s2k identifier
     * @param secKeyData encrypted secret key data with appended AEAD auth tag
     * @return secret key packet
     */
    public static SecretKeyPacket createAeadEncryptedSecretKey(
            PublicKeyPacket pubKeyPacket,
            int encAlgorithm,
            int aeadAlgorithm,
            byte[] aeadNonce,
            S2K s2k,
            byte[] secKeyData)
    {
        return new SecretKeyPacket(pubKeyPacket, encAlgorithm, aeadAlgorithm, USAGE_AEAD, s2k, aeadNonce, secKeyData);
    }

    public int getVersion() {
        return pubKeyPacket.getVersion();
    }

    public int getEncAlgorithm()
    {
        return encAlgorithm;
    }

    public int getAeadAlgorithm() {
        return aeadAlgorithm;
    }

    public int getS2KUsage()
    {
        return s2kUsage;
    }

    public byte[] getIV()
    {
        return iv;
    }

    public S2K getS2K()
    {
        return s2k;
    }

    public PublicKeyPacket getPublicKeyPacket()
    {
        return pubKeyPacket;
    }

    public byte[] getSecretKeyData()
    {
        return secKeyData;
    }

    public byte[] getEncodedContents()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        pOut.write(pubKeyPacket.getEncodedContents());

        pOut.write(s2kUsage);

        // conditional parameters
        byte[] conditionalParameters = encodeConditionalParameters();
        if (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6 && s2kUsage != USAGE_NONE)
        {
            pOut.write(conditionalParameters.length);
        }
        pOut.write(conditionalParameters);

        // encrypted secret key
        if (secKeyData != null && secKeyData.length > 0)
        {
            pOut.write(secKeyData);
        }

        pOut.close();

        return bOut.toByteArray();
    }

    private byte[] encodeConditionalParameters() throws IOException {
        ByteArrayOutputStream conditionalParameters = new ByteArrayOutputStream();
        boolean hasS2KSpecifier = s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD;
        byte[] encodedS2K = hasS2KSpecifier ? s2k.getEncoded() : null;
        if (hasS2KSpecifier)
        {
            conditionalParameters.write(encAlgorithm);
        }
        if (s2kUsage == USAGE_AEAD)
        {
            conditionalParameters.write(aeadAlgorithm);
        }
        if (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6 && hasS2KSpecifier)
        {
            conditionalParameters.write(encodedS2K.length);
        }
        if (hasS2KSpecifier)
        {
            conditionalParameters.write(encodedS2K);
        }
        if (s2kUsage == USAGE_AEAD || iv != null)
        {
            // since USAGE_AEAD and other types that use an IV are mutually exclusive,
            // we use the IV field for both v4 IVs and v6 AEAD nonces
            conditionalParameters.write(iv);
        }
        return conditionalParameters.toByteArray();
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writePacket(SECRET_KEY, getEncodedContents());
    }
}
