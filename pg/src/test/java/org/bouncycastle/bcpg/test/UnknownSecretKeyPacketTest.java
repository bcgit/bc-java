package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MalformedPacketException;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.UnknownBCPGKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class UnknownSecretKeyPacketTest
    extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "UnknownSecretKeyPacketTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        parseUnknownUnencryptedSecretKey();
        parseV6SecretKeyWithUnknownInnerS2KType();
    }

    /**
     * A v6 secret key packet whose USAGE_SHA1 length-prefixed inner S2K block carries an
     * unrecognized S2K type byte must surface as a {@link MalformedPacketException} (an
     * {@link IOException}) from {@link BCPGInputStream#readPacket()}, not as an unchecked
     * {@code UnsupportedPacketVersionException} escaping the contracted IOException parse path.
     */
    private void parseV6SecretKeyWithUnknownInnerS2KType()
        throws IOException
    {
        Date creationTime = new Date((new Date().getTime() / 1000) * 1000);

        // Build a structurally well-formed v6 secret key with a recognized (SALTED_AND_ITERATED) inner S2K,
        // then surgically corrupt only the inner S2K type byte to an unrecognized value.
        byte[] salt = Hex.decode("0001020304050607");
        S2K s2k = new S2K(HashAlgorithmTags.SHA256, salt, 0x60);

        SecretKeyPacket sk = new SecretKeyPacket(
            new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                99,
                creationTime,
                new UnknownBCPGKey(3, Hex.decode("c0ffee"))),
            SymmetricKeyAlgorithmTags.AES_256,
            SecretKeyPacket.USAGE_SHA1,
            s2k,
            Hex.decode("00010203040506070809101112131415"),
            Hex.decode("0decaf"));

        byte[] encoded = sk.getEncoded(PacketFormat.CURRENT);

        // Locate the encoded inner S2K (begins with the SALTED_AND_ITERATED type byte 0x03 followed by the salt)
        // and flip its type byte to 0x99 (153), which is not one of SIMPLE/SALTED/SALTED_AND_ITERATED/ARGON_2/GNU_DUMMY_S2K.
        byte[] s2kEncoded = s2k.getEncoded();
        int s2kOffset = -1;
        for (int i = 0; i + s2kEncoded.length <= encoded.length; i++)
        {
            boolean match = true;
            for (int j = 0; j != s2kEncoded.length; j++)
            {
                if (encoded[i + j] != s2kEncoded[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                s2kOffset = i;
                break;
            }
        }
        isTrue("Could not locate inner S2K in encoded v6 secret key", s2kOffset >= 0);

        byte[] corrupted = Arrays.clone(encoded);
        corrupted[s2kOffset] = (byte)0x99;

        BCPGInputStream pIn = new BCPGInputStream(new ByteArrayInputStream(corrupted));
        try
        {
            pIn.readPacket();
            fail("Expected MalformedPacketException for unknown inner S2K type");
        }
        catch (MalformedPacketException e)
        {
            // expected: malformed input surfaces as a checked IOException subclass
            isTrue("MalformedPacketException should carry the original cause",
                e.getCause() instanceof org.bouncycastle.bcpg.UnsupportedPacketVersionException);
        }
    }

    private void parseUnknownUnencryptedSecretKey()
        throws IOException
    {
        for (int idx = 0; idx != 2; idx ++)
        {
            int version = (idx == 0) ? PublicKeyPacket.LIBREPGP_5 : PublicKeyPacket.VERSION_6;
            Date creationTime = new Date((new Date().getTime() / 1000) * 1000);
            SecretKeyPacket sk = new SecretKeyPacket(
                new PublicKeyPacket(
                    version,
                    99,
                    creationTime,
                    new UnknownBCPGKey(3, Hex.decode("c0ffee"))),
                SymmetricKeyAlgorithmTags.NULL,
                null,
                null,
                Hex.decode("0decaf"));

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
            BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
            sk.encode(pOut);
            pOut.close();
            aOut.close();

            ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
            ArmoredInputStream aIn = new ArmoredInputStream(bIn);
            BCPGInputStream pIn = new BCPGInputStream(aIn);
            SecretKeyPacket p = (SecretKeyPacket) pIn.readPacket();

            isEquals("Packet version mismatch", version, p.getPublicKeyPacket().getVersion());
            isEquals("Algorithm mismatch", 99, p.getPublicKeyPacket().getAlgorithm());
            isEncodingEqual("Public key encoding mismatch", Hex.decode("c0ffee"), p.getPublicKeyPacket().getKey().getEncoded());
            isEncodingEqual("Secret key encoding mismatch", Hex.decode("0decaf"), p.getSecretKeyData());
            isEncodingEqual("Packet encoding mismatch", sk.getEncoded(PacketFormat.CURRENT), p.getEncoded(PacketFormat.CURRENT));
        }
    }

    public static void main(String[] args)
    {
        runTest(new UnknownSecretKeyPacketTest());
    }
}