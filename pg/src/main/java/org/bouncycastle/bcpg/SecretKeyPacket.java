package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
     *     Klíma, V. and T. Rosa,
     *     "Attack on Private Signature Keys of the OpenPGP Format,
     *     PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
     * @see <a href="https://www.kopenpgp.com/">
     *     Bruseghini, L., Paterson, K. G., and D. Huigens,
     *     "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
     * @deprecated Use of MalleableCFB is deprecated.
     *             For v4 keys, use {@link #USAGE_SHA1} instead.
     *             For v6 keys use {@link #USAGE_AEAD} instead.
     */
    @Deprecated
    public static final int USAGE_CHECKSUM = 0xff;

    /**
     * CFB.
     * CFB-encrypted keys are vulnerable to corruption attacks that can
     * cause leakage of secret data when the secret key is use.
     *
     * @see <a href="https://eprint.iacr.org/2002/076">
     *     Klíma, V. and T. Rosa,
     *     "Attack on Private Signature Keys of the OpenPGP Format,
     *     PGP(TM) Programs and Other Applications Compatible with OpenPGP"</a>
     * @see <a href="https://www.kopenpgp.com/">
     *     Bruseghini, L., Paterson, K. G., and D. Huigens,
     *     "Victory by KO: Attacking OpenPGP Using Key Overwriting"</a>
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
    private S2K s2k;
    private byte[] iv;

    /**
     * @param in
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

        s2kUsage = in.read();

        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1)
        {
            encAlgorithm = in.read();
            s2k = new S2K(in);
        }
        else
        {
            encAlgorithm = s2kUsage;
        }

        if (!(s2k != null && s2k.getType() == S2K.GNU_DUMMY_S2K && s2k.getProtectionMode() == 0x01))
        {
            if (s2kUsage != 0)
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
        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;

        if (encAlgorithm != SymmetricKeyAlgorithmTags.NULL)
        {
            this.s2kUsage = USAGE_CHECKSUM;
        }
        else
        {
            this.s2kUsage = USAGE_NONE;
        }

        this.s2k = s2k;
        this.iv = iv;
        this.secKeyData = secKeyData;
    }

    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int encAlgorithm,
        int s2kUsage,
        S2K s2k,
        byte[] iv,
        byte[] secKeyData)
    {
        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;
        this.s2kUsage = s2kUsage;
        this.s2k = s2k;
        this.iv = iv;
        this.secKeyData = secKeyData;
    }

    public int getEncAlgorithm()
    {
        return encAlgorithm;
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

        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1)
        {
            pOut.write(encAlgorithm);
            pOut.writeObject(s2k);
        }

        if (iv != null)
        {
            pOut.write(iv);
        }

        if (secKeyData != null && secKeyData.length > 0)
        {
            pOut.write(secKeyData);
        }

        pOut.close();

        return bOut.toByteArray();
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writePacket(SECRET_KEY, getEncodedContents());
    }
}
