package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.UnknownBCPGKey;
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