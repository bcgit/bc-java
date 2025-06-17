package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class OpenPGPMessageGeneratorTest
    extends APITest
{
    @Override
    public String getName()
    {
        return "OpenPGPMessageGeneratorTest";
    }

    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        armoredLiteralDataPacket(api);
        unarmoredLiteralDataPacket(api);

        armoredCompressedLiteralDataPacket(api);
        unarmoredCompressedLiteralDataPacket(api);

        seipd1EncryptedMessage(api);
        seipd2EncryptedMessage(api);

        seipd2EncryptedSignedMessage(api);
    }

    private void armoredLiteralDataPacket(OpenPGPApi api)
        throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setAllowPadding(false);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write(Strings.toUTF8ByteArray("Hello, World!"));

        msgOut.close();

        String nl = Strings.lineSeparator();
        String expected =
            "-----BEGIN PGP MESSAGE-----" + nl +
                nl +
                "yxNiAAAAAABIZWxsbywgV29ybGQh" + nl +
                "-----END PGP MESSAGE-----" + nl;
        isEquals(expected, bOut.toString());
    }

    private void unarmoredLiteralDataPacket(OpenPGPApi api)
        throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(false) // disable ASCII armor
            .setAllowPadding(false); // disable padding

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write(Strings.toUTF8ByteArray("Hello, World!"));

        msgOut.close();

        isEncodingEqual(Hex.decode("cb1362000000000048656c6c6f2c20576f726c6421"), bOut.toByteArray());
    }

    private void armoredCompressedLiteralDataPacket(OpenPGPApi api)
        throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setAllowPadding(false)
            .setCompressionNegotiator(new OpenPGPMessageGenerator.CompressionNegotiator()
            {
                public int negotiateCompression(OpenPGPMessageGenerator messageGenerator, OpenPGPPolicy policy)
                {
                    return CompressionAlgorithmTags.ZIP;
                }
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write(Strings.toUTF8ByteArray("Hello, World!"));

        msgOut.close();

        String nl = Strings.lineSeparator();
        String expected =
            "-----BEGIN PGP MESSAGE-----" + nl +
                nl +
                "yBUBOy2cxAACHqk5Ofk6CuH5RTkpigA=" + nl +
                "-----END PGP MESSAGE-----" + nl;
        isEquals(expected, bOut.toString());
    }

    private void unarmoredCompressedLiteralDataPacket(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(false) // no armor
            .setAllowPadding(false)
            .setCompressionNegotiator(new OpenPGPMessageGenerator.CompressionNegotiator()
            {
                public int negotiateCompression(OpenPGPMessageGenerator messageGenerator, OpenPGPPolicy policy)
                {
                    return CompressionAlgorithmTags.ZIP;
                }
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream msgOut = gen.open(bOut);

        // Only write a LiteralData packet with "Hello, World!" as content
        msgOut.write(Strings.toUTF8ByteArray("Hello, World!"));

        msgOut.close();

        isEncodingEqual(Hex.decode("c815013b2d9cc400021ea93939f93a0ae1f94539298a00"), bOut.toByteArray());
    }

    private void seipd2EncryptedMessage(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPCertificate cert = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.V6_CERT);

        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addEncryptionCertificate(cert);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = gen.open(bOut);
        encOut.write(Strings.toUTF8ByteArray("Hello, World!"));
        encOut.close();

        System.out.println(bOut);
    }

    private void seipd1EncryptedMessage(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.BOB_KEY);

        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addEncryptionCertificate(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = gen.open(bOut);
        encOut.write(Strings.toUTF8ByteArray("Hello, World!"));
        encOut.close();

        System.out.println(bOut);
    }

    private void seipd2EncryptedSignedMessage(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);

        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setAllowPadding(true)
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
