package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class OpenPGPMessageGeneratorTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "OpenPGPMessageGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        armoredLiteralDataPacket();
        unarmoredLiteralDataPacket();

        armoredCompressedLiteralDataPacket();
        unarmoredCompressedLiteralDataPacket();

        seipd1EncryptedMessage();
        seipd2EncryptedMessage();

        seipd2EncryptedSignedMessage();
    }

    private void armoredLiteralDataPacket()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setIsPadded(false);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEquals(
                "-----BEGIN PGP MESSAGE-----\n" +
                        "\n" +
                        "yxNiAAAAAABIZWxsbywgV29ybGQh\n" +
                        "-----END PGP MESSAGE-----\n",
                bOut.toString());
    }

    private void unarmoredLiteralDataPacket()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setArmored(false); // disable ASCII armor
        gen.setIsPadded(false); // disable padding

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEncodingEqual(Hex.decode("cb1362000000000048656c6c6f2c20576f726c6421"), bOut.toByteArray());
    }

    private void armoredCompressedLiteralDataPacket()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setIsPadded(false);
        OpenPGPMessageGenerator.Configuration configuration = gen.getConfiguration();
        configuration.setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEquals("-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "yBUBOy2cxAACHqk5Ofk6CuH5RTkpigA=\n" +
                "-----END PGP MESSAGE-----\n",
                bOut.toString());
    }

    private void unarmoredCompressedLiteralDataPacket()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.setArmored(false); // no armor
        gen.setIsPadded(false);
        OpenPGPMessageGenerator.Configuration configuration = gen.getConfiguration();
        configuration.setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write("Hello, World!".getBytes(StandardCharsets.UTF_8));

        msgOut.close();

        isEncodingEqual(Hex.decode("c815013b2d9cc400021ea93939f93a0ae1f94539298a00"), bOut.toByteArray());
    }

    private void seipd2EncryptedMessage()
            throws IOException, PGPException
    {
        OpenPGPCertificate cert = OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.V6_CERT);

        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(cert);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = gen.open(bOut);
        encOut.write("Hello World!\n".getBytes(StandardCharsets.UTF_8));
        encOut.close();

        System.out.println(bOut);
    }

    private void seipd1EncryptedMessage()
            throws IOException, PGPException
    {
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.BOB_KEY);

        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = gen.open(bOut);
        encOut.write("Hello World!\n".getBytes(StandardCharsets.UTF_8));
        encOut.close();

        System.out.println(bOut);
    }

    private void seipd2EncryptedSignedMessage()
            throws IOException, PGPException
    {
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.V6_KEY);

        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setIsPadded(true)
                .setArmored(true)
                .addSigningKey(key)
                .addEncryptionCertificate(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = gen.open(bOut);
        encOut.write("Hello, World!\n".getBytes());
        encOut.close();

        System.out.println(bOut);
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPMessageGeneratorTest());
    }
}
