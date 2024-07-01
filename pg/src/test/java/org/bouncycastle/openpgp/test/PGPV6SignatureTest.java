package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class PGPV6SignatureTest
        extends AbstractPacketTest
{

    private static final String ARMORED_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n" +
            "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n" +
            "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n" +
            "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n" +
            "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n" +
            "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n" +
            "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n" +
            "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n" +
            "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String ARMORED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
            "k0mXubZvyl4GBg==\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    @Override
    public String getName()
    {
        return "PGPV6SignatureTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        verifyV6DirectKeySignatureTestVector();

        verifyV6BinarySignature();
        verifyV6InlineSignature();
        verifyV6CleartextSignature();

        verifyingSignatureWithMismatchedSaltSizeFails();
        verifyingOPSWithMismatchedSaltSizeFails();
    }

    private void verifyV6DirectKeySignatureTestVector()
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_CERT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);

        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFac.nextObject();
        PGPPublicKey primaryKey = cert.getPublicKey(Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"));
        PGPPublicKey subkey = cert.getPublicKey(Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"));

        PGPSignature directKeySig = primaryKey.getKeySignatures().next();
        PGPSignature subkeyBinding = subkey.getKeySignatures().next();

        directKeySig.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Direct-Key Signature on the primary key MUST be correct.",
                directKeySig.verifyCertification(primaryKey));

        subkeyBinding.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Subkey-Binding Signature MUST be correct.",
                subkeyBinding.verifyCertification(primaryKey, subkey));
    }

    private void verifyV6BinarySignature()
            throws IOException, PGPException
    {
        String msg = "Hello, World!\n";
        String ARMORED_SIG = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wpgGABsKAAAAKSKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJBYJm\n" +
                "gm9ZAAAAAHbbIIiAPSgC+KgRmEnYT3DlWRRXD3FZbagaoUrQy6hBg+exB/J/zqCD\n" +
                "WQDNfRrJsKzt5NNgDtlpOPwJocYPL3LTvYIDDTTxmD1WFMaeF/mDgo1DJfcRCkXt\n" +
                "PXdpdVaImaOqDA==\n" +
                "-----END PGP SIGNATURE-----";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(ARMORED_SIG.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        PGPSignature binarySig = sigList.get(0);

        binarySig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        binarySig.update(msg.getBytes(StandardCharsets.UTF_8));
        isTrue("Detached binary signature MUST be valid.",
                binarySig.verify());
    }

    private void verifyV6InlineSignature()
            throws IOException, PGPException
    {
        String ARMORED_MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "xEYGAQobIMcgFZRFzyKmYrqqNES9B0geVN5TZ6Wct6aUrITCuFyeyxhsTwYJppfk\n" +
                "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkAyxR1AAAAAABIZWxsbywgV29ybGQhCsKY\n" +
                "BgEbCgAAACkioQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9lJewnutmsyQWCZoJv\n" +
                "WQAAAAAkFSDHIBWURc8ipmK6qjREvQdIHlTeU2elnLemlKyEwrhcnotltzKi2NN+\n" +
                "XNJISXQ0X0f4TppBoHbpmwc5YCTIv2+vDZPI+tjzXL9m2e1jrqqaUMEwQ+Zy8B+K\n" +
                "LC4rA6Gh2gY=\n" +
                "-----END PGP MESSAGE-----";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(ARMORED_MSG.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);

        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 OPS", 1, opsList.size());
        PGPOnePassSignature ops = opsList.get(0);

        ops.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);

        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(lit.getDataStream(), plainOut);

        ops.update(plainOut.toByteArray());
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly one signature", 1, sigList.size());
        PGPSignature sig = sigList.get(0);
        isTrue("Verifying OPS signature MUST succeed", ops.verify(sig));
    }

    private void verifyV6CleartextSignature()
            throws IOException, PGPException
    {
        String CLEARTEXT_MSG = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "\n" +
                "Hello, World!\n" +
                "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wpgGARsKAAAAKSKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJBYJm\n" +
                "gm9ZAAAAAOwrIHtJrY7SIiXXqaBpEbjlJvpviklWkAvMJOLLmVt+hy7wvLNKZEhu\n" +
                "ZKiy7zgFRoXTwtVVHyBlTvRoMKN7NhfN5UoDaV3isn0uipMR7YoZTxacQmg3CQlM\n" +
                "NOaSt0xdZMqnBw==\n" +
                "-----END PGP SIGNATURE-----";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(CLEARTEXT_MSG.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        while (aIn.isClearText())
        {
            int c = aIn.read();
            if (aIn.isClearText())
            {
                plainOut.write(c);
            }
        }
        isEncodingEqual("Plaintext MUST match", "Hello, World!\n".getBytes(StandardCharsets.UTF_8), plainOut.toByteArray());
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 signature.", 1, sigList.size());
        PGPSignature sig = sigList.get(0);
        sig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        sig.update("Hello, World!".getBytes(StandardCharsets.UTF_8));
        isTrue("Signature MUST verify successfully", sig.verify());
    }

    private void verifyingSignatureWithMismatchedSaltSizeFails()
            throws IOException
    {
        // v6 signature made using SHA512 with 16 instead of 32 bytes of salt.
        String armoredSig = "-----BEGIN PGP SIGNATURE-----\n" +
                "Version: BCPG v@RELEASE_NAME@\n" +
                "\n" +
                "wogGABsKAAAAKSKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJBYJm\n" +
                "gXv9AAAAAGHvEIB9K2RLSK++vMVKnivhTgBBHon1f/feri7mJOAYfGm8vOzgbc/8\n" +
                "/zeeT3ZY+EK3q6RQ6W0nolelQejFuy1w9duC8/1U/oTD6iSi1pRAEm4M\n" +
                "=mBNb\n" +
                "-----END PGP SIGNATURE-----";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(armoredSig.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        PGPSignature binarySig = sigList.get(0);

        try
        {
            binarySig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
            fail("Init'ing verification of signature with mismatched salt size MUST fail.");
        }
        catch (PGPException e)
        {
            // expected
        }
    }

    private void verifyingOPSWithMismatchedSaltSizeFails()
            throws IOException
    {
        // v6 signature made using SHA512 with 16 instead of 32 bytes of salt.
        String armoredMsg = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "xDYGAQobEKM41oT/St9iR6qxoR2RndzLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l\n" +
                "JewnutmsyQDLFHUAAAAAAEhlbGxvLCBXb3JsZCEKwogGARsKAAAAKSKhBssYbE8G\n" +
                "CaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJBYJmgXv9AAAAAHU6EKM41oT/St9i\n" +
                "R6qxoR2RndzKyHgSHsO9QIzLibxeWtny69R0srOsJVFr153JlXSlUojGxv00QvlY\n" +
                "z90jECs8awk7vCeJxTHrHFL01Xy5sTsN\n" +
                "-----END PGP MESSAGE-----";

        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(armoredMsg.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);

        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 OPS", 1, opsList.size());
        PGPOnePassSignature ops = opsList.get(0);

        try
        {
            ops.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
            fail("Init'ing verification of OPS with mismatched salt size MUST fail.");
        }
        catch (PGPException e)
        {
            // expected.
        }
    }

    public static void main(String[] args)
    {
        runTest(new PGPV6SignatureTest());
    }
}
