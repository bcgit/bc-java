package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;
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
    private byte[] aeadNonce;
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

        int version = pubKeyPacket.getVersion();
        s2kUsage = in.read();

        if (s2kUsage == USAGE_CHECKSUM || s2kUsage == USAGE_SHA1)
        {
            encAlgorithm = in.read();
            if (version == VERSION_6) {
                // TODO: Use length-octet to enable parsing unknown S2Ks.
                in.read();
            }
            s2k = new S2K(in);
        }
        else if (s2kUsage == USAGE_AEAD)
        {
            encAlgorithm = in.read();
            aeadAlgorithm = in.read();
            if (version == 5 || version == 6)
            {
                in.read();
            }
            s2k = new S2K(in);
            aeadNonce = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
            Streams.readFully(in, aeadNonce);
        }
        else
        {
            encAlgorithm = s2kUsage;
        }

        boolean isGNUDummyNoPrivateKey = s2k != null &&
                s2k.getType() == S2K.GNU_DUMMY_S2K &&
                s2k.getProtectionMode() == S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY;
        if (!(isGNUDummyNoPrivateKey))
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
            this.s2kUsage = USAGE_SHA1;
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

    public int getAeadAlgorithm() {
        return aeadAlgorithm;
    }

    public byte[] getAeadNonce() {
        return Arrays.clone(aeadNonce);
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

        // prepare conditional parameters
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
        if (s2kUsage == USAGE_AEAD)
        {
            conditionalParameters.write(aeadNonce);
        }
        if (iv != null)
        {
            conditionalParameters.write(iv);
        }

        // write length of conditional parameters
        if (pubKeyPacket.getVersion() == PublicKeyPacket.VERSION_6 && s2kUsage != USAGE_NONE)
        {
            pOut.write(conditionalParameters.size());
        }
        // write conditional parameters
        pOut.write(conditionalParameters.toByteArray());

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
