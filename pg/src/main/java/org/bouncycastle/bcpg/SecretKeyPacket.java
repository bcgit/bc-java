package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.io.Streams;

/**
 * basic packet for a PGP secret key
 */
public class SecretKeyPacket
    extends ContainedPacket
    implements PublicKeyAlgorithmTags
{
    /**
     * Unprotected.
     */
    public static final int USAGE_NONE = 0x00;

    /**
     * Malleable CFB.
     * Malleable-CFB-encrypted keys are vulnerable to corruption attacks
     * that can cause leakage of secret data when the secret key is used.
     *
     * @see <a href="https://eprint.iacr.org/2002/076">
     * Klíma, V. and T. Rosa,
     * "Attack on Private Signature Keys of the OpenPGP Format,
     * PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
     * @see <a href="https://www.kopenpgp.com/">
     * Bruseghini, L., Paterson, K. G., and D. Huigens,
     * "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
     * @deprecated Use of MalleableCFB is deprecated.
     * For v4 keys, use {@link #USAGE_SHA1} instead.
     * For v6 keys use {@link #USAGE_AEAD} instead.
     */
    public static final int USAGE_CHECKSUM = 0xff;

    /**
     * CFB.
     * CFB-encrypted keys are vulnerable to corruption attacks that can
     * cause leakage of secret data when the secret key is use.
     *
     * @see <a href="https://eprint.iacr.org/2002/076">
     * Klíma, V. and T. Rosa,
     * "Attack on Private Signature Keys of the OpenPGP Format,
     * PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
     * @see <a href="https://www.kopenpgp.com/">
     * Bruseghini, L., Paterson, K. G., and D. Huigens,
     * "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
     */
    public static final int USAGE_SHA1 = 0xfe;

    /**
     * AEAD.
     * This usage protects against above-mentioned attacks.
     * Passphrase-protected secret key material in a v6 Secret Key or
     * v6 Secret Subkey packet SHOULD be protected with AEAD encryption
     * unless it will be transferred to an implementation that is known
     * to not support AEAD.
     * Users should migrate to AEAD with all due speed.
     */
    public static final int USAGE_AEAD = 0xfd;

    private PublicKeyPacket pubKeyPacket;
    private byte[] secKeyData;
    private int s2kUsage;
    private int encAlgorithm;
    private int aeadAlgorithm;
    private S2K s2k;
    private byte[] iv;

    SecretKeyPacket(
        BCPGInputStream in)
        throws IOException
    {
        this(SECRET_KEY, in);
    }

    /**
     * @param in
     * @throws IOException
     */
    SecretKeyPacket(
        int keyTag,
        BCPGInputStream in)
        throws IOException
    {
        super(keyTag);

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

        if (version == 6 && s2kUsage != USAGE_NONE)
        {
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
        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD)
        {
            if (version == PublicKeyPacket.VERSION_6)
            {
                // TODO: Use length to parse unknown S2Ks
                int s2kLen = in.read();
            }
            s2k = new S2K(in);
        }
        if (s2kUsage == USAGE_AEAD)
        {
            iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
            Streams.readFully(in, iv);
        }
        boolean isGNUDummyNoPrivateKey = s2k != null
                && s2k.getType() == S2K.GNU_DUMMY_S2K
                && s2k.getProtectionMode() == S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY;
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
     * @param pubKeyPacket
     * @param encAlgorithm
     * @param s2k
     * @param iv
     * @param secKeyData
     */
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(SECRET_KEY, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData);
    }

    SecretKeyPacket(
        int keyTag,
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(keyTag, pubKeyPacket, encAlgorithm, 0, encAlgorithm != SymmetricKeyAlgorithmTags.NULL ? USAGE_CHECKSUM : USAGE_NONE, s2k, iv, secKeyData);
    }

    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this(SECRET_KEY, pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData);
    }

    SecretKeyPacket(
        int keyTag,
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int aeadAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        super(keyTag);

        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;
        this.aeadAlgorithm = aeadAlgorithm;
        this.s2kUsage = s2kUsage;
        this.s2k = s2k;
        this.iv = iv;
        this.secKeyData = secKeyData;

        if (s2k != null && s2k.getType() == S2K.ARGON_2 && s2kUsage != USAGE_AEAD)
        {
            throw new IllegalArgumentException("Argon2 is only used with AEAD (S2K usage octet 253)");
        }

        if (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6)
        {
            if (s2kUsage == USAGE_CHECKSUM)
            {
                throw new IllegalArgumentException("Version 6 keys MUST NOT use S2K usage USAGE_CHECKSUM");
            }
        }
    }

    public int getEncAlgorithm()
    {
        return encAlgorithm;
    }

    public int getAeadAlgorithm()
    {
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

    private byte[] encodeConditionalParameters()
        throws IOException
    {
        ByteArrayOutputStream conditionalParameters = new ByteArrayOutputStream();
        boolean hasS2KSpecifier = s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1 || s2kUsage == USAGE_AEAD;

        if (hasS2KSpecifier)
        {
            conditionalParameters.write(encAlgorithm);
            if (s2kUsage == USAGE_AEAD)
            {
                conditionalParameters.write(aeadAlgorithm);
            }
            byte[] encodedS2K = s2k.getEncoded();
            if (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6)
            {
                conditionalParameters.write(encodedS2K.length);
            }
            conditionalParameters.write(encodedS2K);
        }
        if (iv != null)
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
        out.writePacket(getPacketTag(), getEncodedContents());
    }
}
