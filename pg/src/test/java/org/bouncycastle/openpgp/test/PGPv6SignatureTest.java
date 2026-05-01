package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class PGPv6SignatureTest
    extends AbstractPacketTest
{
    // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-certificat
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
    // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-secret-key
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
        return "PGPv6SignatureTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        verifySignatureOnTestKey();
        verifyKnownGoodCleartextSignedMessage();

        verifyV6DetachedSignature();
        verifyV6InlineSignature();
        verifyV6CleartextSignature();

        generateAndVerifyV6DetachedSignature();
        generateAndVerifyV6InlineSignature();
        generateAndVerifyV6CleartextSignature();

        verifyingSignatureWithMismatchedSaltSizeFails();
        verifyingOPSWithMismatchedSaltSizeFails();
        verifyingInlineSignatureWithSignatureSaltValueMismatchFails();

        verifySignaturesOnEd448X448Key();
        generateAndVerifyInlineSignatureUsingRSAKey();

        testVerificationOfV4SigWithV6KeyFails();
    }

    /**
     * Verify that the known-good key signatures on the minimal test key verify properly.
     */
    private void verifySignatureOnTestKey()
        throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_CERT));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);

        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFac.nextObject();
        PGPPublicKey primaryKey = cert.getPublicKey(Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"));
        PGPPublicKey subkey = cert.getPublicKey(Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"));

        PGPSignature directKeySig = (PGPSignature)primaryKey.getKeySignatures().next();
        PGPSignature subkeyBinding = (PGPSignature)subkey.getKeySignatures().next();

        directKeySig.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Direct-Key Signature on the primary key MUST be correct.",
            directKeySig.verifyCertification(primaryKey));

        subkeyBinding.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Subkey-Binding Signature MUST be correct.",
            subkeyBinding.verifyCertification(primaryKey, subkey));
    }

    private void verifyKnownGoodCleartextSignedMessage() throws IOException, PGPException {
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-cleartext-signed-mes
        String MSG = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "\n" +
                "What we need from the grocery store:\n" +
                "\n" +
                "- - tofu\n" +
                "- - vegetables\n" +
                "- - noodles\n" +
                "\n" +
                "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo\n" +
                "/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr\n" +
                "NK2ay45cX1IVAQ==\n" +
                "-----END PGP SIGNATURE-----";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_CERT));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFac.nextObject();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(MSG));
        aIn = new ArmoredInputStream(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        while (aIn.isClearText())
        {
            int c = aIn.read();
            if (aIn.isClearText())
            {
                bOut.write(c);
            }
        }
        byte[] plaintext = Arrays.copyOf(bOut.toByteArray(), bOut.size()- 1);
        objFac = new BcPGPObjectFactory(aIn);
        PGPSignatureList sigs = (PGPSignatureList) objFac.nextObject();
        PGPSignature sig = sigs.get(0);
        sig.init(new BcPGPContentVerifierBuilderProvider(), cert.getPublicKey(sig.getKeyID()));
        sig.update(plaintext);
        isTrue("Known good cleartext signature MUST verify successful", sig.verify());
    }

    /**
     * Verify that a good v6 detached signature is verified properly.
     */
    private void verifyV6DetachedSignature()
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

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_SIG));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        PGPSignature binarySig = sigList.get(0);

        binarySig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        binarySig.update(Strings.toUTF8ByteArray(msg));
        isTrue("Detached binary signature MUST be valid.",
            binarySig.verify());
    }

    /**
     * Verify that a good v6 inline signature is verified properly.
     */
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

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_MSG));
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

    /**
     * Verify that a good v6 cleartext signature is verified properly.
     */
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

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(CLEARTEXT_MSG));
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
        isEncodingEqual("Plaintext MUST match",
                Strings.toUTF8ByteArray("Hello, World!\n"), plainOut.toByteArray());
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 signature.", 1, sigList.size());
        PGPSignature sig = sigList.get(0);
        sig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        sig.update(Strings.toUTF8ByteArray("Hello, World!"));
        isTrue("Cleartext Signature MUST verify successfully", sig.verify());
    }

    /**
     * A v6 signature with too few salt bytes.
     * This test verifies that the signature is properly rejected.
     */
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

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(armoredSig));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        PGPSignature binarySig = sigList.get(0);

        try
        {
            binarySig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
            fail("Initiating verification of signature with mismatched salt size MUST fail.");
        }
        catch (PGPException e)
        {
            // expected
        }
    }

    /**
     * Verify that a OPS signature where the length of the salt array does not match the expectations
     * is rejected properly.
     */
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

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(armoredMsg));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);

        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 OPS", 1, opsList.size());
        PGPOnePassSignature ops = opsList.get(0);

        try
        {
            ops.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
            fail("Initiating verification of OPS with mismatched salt size MUST fail.");
        }
        catch (PGPException e)
        {
            // expected.
        }
    }

    /**
     * Test verifying that an inline signature where the salt of the OPS packet mismatches that of the signature
     * is rejected properly.
     */
    private void verifyingInlineSignatureWithSignatureSaltValueMismatchFails()
        throws IOException, PGPException
    {
        String ARMORED_MSG = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "xEYGAQobIMcgFZRFzyKmYrqqNES9B0geVN5TZ6Wct6aUrITCuFyeyxhsTwYJppfk\n" +
            "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkAyxR1AAAAAABIZWxsbywgV29ybGQhCsKY\n" +
            "BgEbCgAAACkioQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9lJewnutmsyQWCZoJv\n" +
            "WQAAAAAkFSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAItltzKi2NN+\n" +
            "XNJISXQ0X0f4TppBoHbpmwc5YCTIv2+vDZPI+tjzXL9m2e1jrqqaUMEwQ+Zy8B+K\n" +
            "LC4rA6Gh2gY=\n" +
            "=KRD3\n" +
            "-----END PGP MESSAGE-----";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        PGPPublicKey signingPubKey = secretKeys.getPublicKey();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_MSG));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);

        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) objFac.nextObject();
        PGPOnePassSignature ops = opsList.get(0);
        isEncodingEqual("OPS salt MUST match our expectations.",
            Hex.decode("C720159445CF22A662BAAA3444BD07481E54DE5367A59CB7A694AC84C2B85C9E"),
            ops.getSalt());

        ops.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);

        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(lit.getDataStream(), plainOut);

        ops.update(plainOut.toByteArray());
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        PGPSignature sig = sigList.get(0);

        try
        {
            ops.verify(sig);
            fail("Verifying signature with mismatched salt MUST fail.");
        }
        catch (PGPException e)
        {
            // expected
        }
    }

    /**
     * Verify self signatures on a v6 Ed448/X448 key.
     */
    private void verifySignaturesOnEd448X448Key()
        throws PGPException, IOException
    {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: 8cf27d01 f6160563 9e4b8525 353c0cfb  f5a23e45 96c47fe6 d90ccacf 3293d5d6\n" +
            "Comment: 93c07acb 9eef9fa2 346ac1d5 ff50051c  96124504 e2fb3b5b 564bf969 16d28d42\n" +
            "Comment: Ed <ed448@example.com>\n" +
            "\n" +
            "xX8GZovgyRwAAAA529b1jdB2Cgndd45hbN3qxpTbTM9IpdLJ8ibifS5ranMF8g+w\n" +
            "vQfvV2HNwONn1mC+/7yxGLzW9YQAAMM1xRUHrZdL6vcIOugjQ9YDzaoM8nV+6RfN\n" +
            "05CJCcJLp2eM0t015rw6UCcGGL7gy5TOFeLhGMU59x2IwsAjBh8cDgAAAEIFgmaL\n" +
            "4MkDCwkHBRUKDggMAhYAApsDAh4JIiEGjPJ9AfYWBWOeS4UlNTwM+/WiPkWWxH/m\n" +
            "2QzKzzKT1dYFJwkCBwIAAAAA9fcgS0FBeDv6TwF/camy0KEZRHDNIpEI0upB+4vU\n" +
            "kyYab1MiKfpfIkZfqCFCikuR8yW6yIFKNXQK/B9nemfwzq6UNrdUZkZL9BpUfXsq\n" +
            "xlOJ3ksehQrH8SM9ZgAkk+H0WQyKgakBmw8T74vz44Pej2oAU8w50OtJ81duKIdN\n" +
            "bsFF0WiU1PYeLbEPfDjnB2x1lINQCQDNFkVkIDxlZDQ0OEBleGFtcGxlLmNvbT7C\n" +
            "wAoGExwKAAAAKQWCZovgySIhBozyfQH2FgVjnkuFJTU8DPv1oj5FlsR/5tkMys8y\n" +
            "k9XWAAAAADlTIC14mbBrJQ9/qWzRmS5FHVcJkx87OZ9/573lMDcNM+sMIUQP8b/L\n" +
            "c2sLKtzGpQGXG1ETp/MOlGSQaMF6l/3eQpnVZg3jEO0Qd2040Leq4TQqNaFJBMmt\n" +
            "wg2ADddE3CkwzMhBG00yhppY2p6xsvGgYVz3vMCQ2MnH/0Hj+9bmzSoJDM/4gXe3\n" +
            "HXI1kuEOPFINmi0Ax30GZovgyRoAAAA4SRrAL6zM93X89gPFjMA3D9vjprB0pB7m\n" +
            "fVr/c3UPaS/H5ILrcgbvcpwf+D7H1n2DZq2N4MqXvzoANBS7o2zj3FQO80Reagx2\n" +
            "ZTav2DzRHNl4M626qkGyUD4u393yIU0u8KMPTZstT43zWqVn3ZzPJJAbdcLADQYY\n" +
            "HA4AAAAsIiEGjPJ9AfYWBWOeS4UlNTwM+/WiPkWWxH/m2QzKzzKT1dYFgmaL4MkC\n" +
            "mwwAAAAAGPAg10+uyPMPtyB8bomChz/rokK7pTV5AgIjulbOuEVSLkQPXRn06gMn\n" +
            "TleudzUKY3mh3Cm01DAVg+5GWQz9F0qWebwzsjUiGqMt7ovySZw4Qkv+lBPkKSxN\n" +
            "uwDxqjLecoGbL6nM4mGMU+27dlZRjjpHVWRGur6tup5IBWsX97zKYYrsTE2HCVOC\n" +
            "rm3bgQD1eeP0CQA=\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
        verifySignaturesOnKey(KEY);
    }

    private void verifySignaturesOnKey(String armoredKey)
        throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(armoredKey));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        Iterator<PGPPublicKey> pubKeys = secretKeys.getPublicKeys();
        PGPPublicKey primaryKey = (PGPPublicKey)pubKeys.next();

        Iterator<PGPSignature> directKeySigs = primaryKey.getSignaturesOfType(PGPSignature.DIRECT_KEY);
        while (directKeySigs.hasNext())
        {
            PGPSignature dkSig = (PGPSignature)directKeySigs.next();
            PGPPublicKey sigKey = getSigningKeyFor(secretKeys, dkSig);
            if (sigKey != null)
            {
                dkSig.init(new BcPGPContentVerifierBuilderProvider(), sigKey);
                isTrue("Direct-Key Signature MUST verify", dkSig.verifyCertification(sigKey));
            }
            else
            {
                // -DM System.out.println
                System.out.println("Did not find signing key for DK sig");
            }
        }

        Iterator<String> uids = primaryKey.getUserIDs();
        while (uids.hasNext())
        {
            String uid = (String)uids.next();
            Iterator<PGPSignature> uidSigs = primaryKey.getSignaturesForID(uid);
            while (uidSigs.hasNext())
            {
                PGPSignature uidSig = (PGPSignature)uidSigs.next();
                PGPPublicKey sigKey = getSigningKeyFor(secretKeys, uidSig);
                if (sigKey != null)
                {
                    uidSig.init(new BcPGPContentVerifierBuilderProvider(), sigKey);
                    isTrue("UID Signature for " + uid + " MUST verify",
                        uidSig.verifyCertification(uid, sigKey));
                }
                else
                {
                    // -DM System.out.println
                    System.out.println("Did not find signing key for UID sig for " + uid);
                }
            }
        }

        while (pubKeys.hasNext())
        {
            PGPPublicKey subkey = (PGPPublicKey)pubKeys.next();
            Iterator<PGPSignature> bindSigs = subkey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
            while (bindSigs.hasNext())
            {
                PGPSignature bindSig = (PGPSignature)bindSigs.next();
                PGPPublicKey sigKey = getSigningKeyFor(secretKeys, bindSig);
                if (sigKey != null)
                {
                    bindSig.init(new BcPGPContentVerifierBuilderProvider(), sigKey);
                    isTrue("Subkey binding signature MUST verify",
                        bindSig.verifyCertification(sigKey, subkey));
                }
                else
                {
                    // -DM System.out.println
                    // -DM Hex.toHexString
                    System.out.println("Did not find singing key for subkey " + Hex.toHexString(subkey.getFingerprint()) + " binding signature");
                }
            }
        }
    }

    private PGPPublicKey getSigningKeyFor(PGPKeyRing keys, PGPSignature sig)
    {
        Iterator<PGPPublicKey> pubKeys = keys.getPublicKeys();
        while (pubKeys.hasNext())
        {
            PGPPublicKey k = (PGPPublicKey)pubKeys.next();
            if (k.getKeyID() == sig.getKeyID())
            {
                return k;
            }

            SignatureSubpacket[] subpackets = sig.getHashedSubPackets().getSubpackets(SignatureSubpacketTags.ISSUER_FINGERPRINT);
            for (int idx = 0; idx != subpackets.length; idx++)
            {
                SignatureSubpacket p = subpackets[idx];
                IssuerFingerprint fp = (IssuerFingerprint) p;
                if (Arrays.areEqual(k.getFingerprint(), fp.getFingerprint()))
                {
                    return k;
                }
            }

            subpackets = sig.getHashedSubPackets().getSubpackets(SignatureSubpacketTags.ISSUER_FINGERPRINT);
            for (int idx = 0; idx != subpackets.length; idx++)
            {
                SignatureSubpacket p = subpackets[idx];
                IssuerFingerprint fp = (IssuerFingerprint) p;
                if (Arrays.areEqual(k.getFingerprint(), fp.getFingerprint()))
                {
                    return k;
                }
            }
        }
        return null;
    }

    /**
     * Generate and verify a detached v6 signature using the v6 test key.
     */
    private void generateAndVerifyV6DetachedSignature()
            throws IOException, PGPException
    {
        String msg = "Hello, World!\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        PGPSecretKey signingSecKey = secretKeys.getSecretKey(); // primary key
        PGPPrivateKey signingPrivKey = signingSecKey.extractPrivateKey(null);
        PGPPublicKey signingPubKey = signingSecKey.getPublicKey();
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(
                        signingPubKey.getAlgorithm(),
                        HashAlgorithmTags.SHA512),
                signingPubKey);
        sigGen.init(PGPSignature.BINARY_DOCUMENT, signingPrivKey);
        sigGen.update(Strings.toUTF8ByteArray(msg));
        PGPSignature binarySig = sigGen.generate();

        binarySig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        binarySig.update(Strings.toUTF8ByteArray(msg));
        isTrue("Detached binary signature MUST verify successful.",
                binarySig.verify());
    }

    /**
     * Generate and verify a v6 inline signature using the v6 test key.
     */
    private void generateAndVerifyV6InlineSignature()
            throws IOException, PGPException
    {
        String msg = "Hello, World!\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        PGPSecretKey signingSecKey = secretKeys.getSecretKey(); // primary key
        PGPPrivateKey signingPrivKey = signingSecKey.extractPrivateKey(null);
        PGPPublicKey signingPubKey = signingSecKey.getPublicKey();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
                .clearHeaders()
                .enableCRC(false)
                .build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(signingPubKey.getAlgorithm(), HashAlgorithmTags.SHA512), signingPubKey);
        sigGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, signingPrivKey);
        sigGen.generateOnePassVersion(true).encode(pOut);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(pOut, PGPLiteralDataGenerator.UTF8, "", PGPLiteralDataGenerator.NOW, new byte[512]);

        litOut.write(Strings.toUTF8ByteArray(msg));
        litOut.close();

        sigGen.update(Strings.toUTF8ByteArray(msg));
        sigGen.generate().encode(pOut);

        pOut.close();
        aOut.close();

        bIn = new ByteArrayInputStream(bOut.toByteArray());
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
        isEncodingEqual("Content of LiteralData packet MUST match plaintext",
                Strings.toUTF8ByteArray(msg), plainOut.toByteArray());

        ops.update(plainOut.toByteArray());
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly one signature", 1, sigList.size());
        PGPSignature sig = sigList.get(0);
        isTrue("Generated Inline OPS signature MUST verify successful", ops.verify(sig));
    }

    /**
     * Generate and verify a v6 signature using the cleartext signature framework and the v6 test key.
     */
    private void generateAndVerifyV6CleartextSignature()
            throws IOException, PGPException
    {
        String msg = "Hello, World!\n";
        String msgS = "Hello, World!";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        PGPSecretKey signingSecKey = secretKeys.getSecretKey(); // primary key
        PGPPrivateKey signingPrivKey = signingSecKey.extractPrivateKey(null);
        PGPPublicKey signingPubKey = signingSecKey.getPublicKey();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
                .clearHeaders()
                .enableCRC(false)
                .build(bOut);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(signingPubKey.getAlgorithm(), HashAlgorithmTags.SHA512),
                signingPubKey);
        sigGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, signingPrivKey);

        aOut.beginClearText(HashAlgorithmTags.SHA512);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        sigGen.update(Strings.toUTF8ByteArray(msgS));
        aOut.write(Strings.toUTF8ByteArray(msg));

        aOut.endClearText();
        sigGen.generate().encode(pOut);
        pOut.close();
        aOut.close();

        // Verify
        bIn = new ByteArrayInputStream(bOut.toByteArray());
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
        isEncodingEqual("Plaintext MUST match", Strings.toUTF8ByteArray(msg), plainOut.toByteArray());
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        isEquals("There MUST be exactly 1 signature.", 1, sigList.size());
        PGPSignature sig = sigList.get(0);
        sig.init(new BcPGPContentVerifierBuilderProvider(), signingPubKey);
        sig.update(Strings.toUTF8ByteArray(msgS));
        boolean v = sig.verify();
        if (!v)
        {
            // -DM System.out.println
            System.out.println(bOut);
        }
        isTrue("Generated Cleartext Signature MUST verify successfully", v);
    }

    /**
     * Generate and verify an inline text signature using a v6 RSA key.
     */
    private void generateAndVerifyInlineSignatureUsingRSAKey()
            throws PGPException, IOException
    {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: B79E376A49446A250AB1738F657EAA7E8F91796B3CA950263C38FBBBEADC2352\n" +
                "\n" +
                "xcZaBmbHNIkBAAACBxAAuastS0RHPZwMZ70ii4hbfOxC3+7bwhVjlAvmp7ZYcShe\n" +
                "96bfDEv+8ydU2oqKbFtokL5pJ3iZhG8h74iYE2E74BQjgEqpFTzc26MjpbbRnldK\n" +
                "BiDpXEiBrDke49ycVkgXFXIUyMLSNNZ2FJTgJenFtjfevFAZTSDMjhr3MebD3TPL\n" +
                "dipor45D4W7GmEqOBpMju3XX31HFq1ON/KPHYCJuVOoGj9UMgpDg1xNhxiq5cqLu\n" +
                "OYmp/PU4YaHgvXsA6w2QKjfA9aDaDmidWtuzzDYM1KfcC0bht1iQYLlPgG9XOe3F\n" +
                "+IHEJ9riviInOqrLeiYKJ2RW9ZT5C6Db2+lV3Fz3bYfNgXjY+BaUG1y3JdwFnvcR\n" +
                "qxawqRCHHeHzmhD4+QwKxjkNQG+jl/s8Vtng1E5GopOe7t38KCnm2A6hnLIvUN4z\n" +
                "0RjU95vA5o+e+x7I4RuCCi2iOqZoLIhQ4JstR+c2Nz8AQ/mXCAzw1EfrndtENyur\n" +
                "FK2/ocBz59UVYHucPvgnSa4gKKVgB1DIBsDAA9Y7/HnMYdJlN6LJoFj6En/4CPlo\n" +
                "WOqytXdDdFwtE5p9yZFJxXCpcwkOaupTTVBepXgzb6MMq4b8YU1pGCaK7EHC4P47\n" +
                "OEZB8/WhXmGyEfU0KWDvje+UG3A/BvqRmWERwAEb1+VcXpRo6b01FWLK6stjlI8A\n" +
                "EQEAAQAP/RDguCnW55j4pgIKJelEOHjXK08a8fwnIJm1KT8GquyCbHubvjvqbp8g\n" +
                "7Kw/Gs011AAQZxOw+VeaGJ4jLxvX427/tah0YQFuum722gc24sA/lBmRhVUfvDXx\n" +
                "LVcuV0HapMqMx8nmN+CYvDwrumKH6TKiyosYxuwFdsLWPbFaFmT1z+GKgmCvEIme\n" +
                "Hcx7PoTnfECOulRxJQRpgIc+RiH9j0UFzxnlFpGJ5P54IxO2D4yVtg0h8ANwMTNi\n" +
                "2UCwPUmgvoGv9sj9WcUkimVXgnUmVq1AIxcdVuhpUxqPzePRez7nV+86sJ+k3KbH\n" +
                "CQTiwMN2UMb67pK9e5Qsh7/qaqUxCEbTfc8QZb9qygN5t3V0Zb1tYxlk7mqGyFa/\n" +
                "g5i4hAfmkwUxgafqr4s8ZuCo5VjbX2KvO1tMDnL/7Ywv2FLx+FZiCdWNIXE7IM1Z\n" +
                "9zXFOLvFQ1SL5aHJ+2NoOqyJpmH50DoI3483qMEu4R/GKqhbJOyk8Ta95SV/lAcf\n" +
                "lBcIjWOWgd6qXzhi3QCoDGSFH7KYQdJkJ3gKYSer9ETCb4ZHWMBxHeWaSeL8WsWd\n" +
                "1feX+Job9CJ/Kd5d9pCDQOeXd3MNFf5TNmEAU3z7+B71eTvlYpNwYvBvH9h4XKbR\n" +
                "Z3GJsvt/kPttEx7wAfiNSeXH9pzWqmbqLpRofxiwnF7mIPc9I5vxCADRfxtk8eWZ\n" +
                "ilCYBEmnfXiKWcU0/pfD8KEfdWv4Btng0LdZCkSL+i8i8ldUxOsLWM+ge9uy3zHc\n" +
                "ms1jIrSZg5FW6XvGG1zcn5PaJqd/nizk7lnqDwHZXRePRtaLF8D0jFXAGAgUr7zI\n" +
                "n2LdDGabvxSsoTWIbWT6z+UzRsZlsOwEXeOpIuAG3kjPamPtxpJoPn15AJ/kpnxG\n" +
                "XsOdGH1FvyIxOp+31sqO8fbjW5NacuzaOvJAvt2JOV5b8rcbnNyIu5pn5YjZ876T\n" +
                "i4K+jrGlByDVUB8IWILe2N0sgVrhTNTO4tqysWHir0SM+s/dSa9OISHpMLChGI08\n" +
                "UH/eZAP9msC/CADi4gX8UdH8wEzaceFur03jXDqIhG8jr2jDVmZ4eyj2NDPZuQ45\n" +
                "J4LuPgytx+RU8edgoB6POZ8TdLr2llA5XBYOVsqBttE7GadULlIDZYgagzIiWc34\n" +
                "VDkxPepWFlwTa5nQ09GeC6H/h594TaaCOHZGJqeD3MJWfrPnj7V+upw+beJeB8Hs\n" +
                "PwfgTuTesjWNK1b/g0dLvF3D7+8z4xlj8iMj80B8Kwl4lSC23W2wd79SC0KvKM4D\n" +
                "dJoA0A9u1KB/hs/qUMllDsRlS0UyWV/R7slK9OdZh742jhluKJ4a/jQ2EihlXMMW\n" +
                "RyLHjRKdT5U7Ou16gXehu7Hrx+EEcKPkt1AxB/0acvo9+ipYTqfV0j8zIH+/m4D0\n" +
                "mtFPRiQi/XviyHIHHsyEx7JHkegynqdU1a6NxAi/o4VNXkSVTFcarln6sxrRmDbg\n" +
                "Uaxc2pcXMXXzfpbW/jjobOGOBLCRJSzV5NbGknm0VAIaOm/ln4d8PT+FydoNhxEr\n" +
                "7fgqtl/hAJ9F1QJeol3cHioJzJ7ye6vMLLIYCdiZAoHMijKOiLAUca3svIqG1Nxw\n" +
                "iUuX6F3ZUvpcG1utgVt8psibOtQGHwJmOGTIEscGVynrVrxZiUhcUmXdW3VaAQAb\n" +
                "2esz7bth6DWbJaKWWxtBkehliuX6A/h//izVCZAb6c05bn3farOe+MrTH9hlwsGz\n" +
                "Bh8BDgAAAEIioQa3njdqSURqJQqxc49lfqp+j5F5azypUCY8OPu76twjUgWCZsc0\n" +
                "iQMLCQcFFQoOCAwCFgACmw8CHgkFJwkCBwIAAAAABo0g9kgtw8wX6XUKcHhtGlLb\n" +
                "fnXOPPHli+iBxjB3y6txtdoQALSr99MU7kF/WbzQNvpdkejLOr6tTxrNHHE5Iw1+\n" +
                "12t1KprbJV/ViDmJ2GGwSiK5bzhA6jtrfFoSQBLKkJ2IoACPSbA80tazUf4E/P2/\n" +
                "+157aU3FQfkT8HS6Zcr604xmw1IemkqMxoN/ukyihz+6MJpltb5kgpE2UNgz07jd\n" +
                "cpXXe4ATKRWIx4I4pVIcXomH9rHDgSLn+bxaCsbfgijnQjJvTJof15rFYGVKtAzx\n" +
                "DYGE2Y7NlCtbveoLj0+e8t2vDJSISBur+9oPgMHR0DbGT7wAr32kWXDFxVl1pU8o\n" +
                "KzQ3QaKNddvMnZ9SyP8OUOc0DlevT0Ib+t2mFvU2omcerI9uUAOut4HrJX3bsAFq\n" +
                "/vC8/pzYLN52sqC6sLrgws28DmMVvN/slK73y5EM+7bkztdJeuHMlED4IRXNQ/tZ\n" +
                "Erm2KYsjzFVLcgk6M9lDLGwi6NKEBfBxwn01r3AhmeGB9n0whSZE4WtEmB/GgT9d\n" +
                "9bC6pOYQeVE+5GPhWbrDCtRBxwXxskXwRrC+/HCM4AwecNfDF5cRJfEAAnxY5G7o\n" +
                "hgHqwbkfY8vm9ePYDJv5+SplEbAQyHaKdKxzeOM6mrpxkkn4tN23ToU14rl17+3d\n" +
                "eGk3VrSlmawnZyRSDguwZst2mcy/MYL+YLYvYTUalXZegP9uRm0YF4RGvnk9PLlg\n" +
                "4M2U\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        String MSG = "Hello, World!\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
                .clearHeaders()
                .enableCRC(false)
                .build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(
                        secretKeys.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA3_512),
                secretKeys.getPublicKey());
        sigGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, secretKeys.getSecretKey().extractPrivateKey(null));
        PGPOnePassSignature ops = sigGen.generateOnePassVersion(false);
        ops.encode(pOut);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(pOut, PGPLiteralDataGenerator.UTF8, "",
                PGPLiteralDataGenerator.NOW, new byte[512]);
        byte[] plaintext = Strings.toUTF8ByteArray(MSG);
        litOut.write(plaintext);
        litOut.close();
        sigGen.update(plaintext);
        PGPSignature sig = sigGen.generate();
        sig.encode(pOut);
        pOut.close();
        aOut.close();

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);

        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) objFac.nextObject();
        ops = opsList.get(0);
        ops.init(new BcPGPContentVerifierBuilderProvider(), secretKeys.getPublicKey());
        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        InputStream litIn = lit.getDataStream();
        plaintext = Streams.readAll(litIn);
        ops.update(plaintext);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();
        sig = sigList.get(0);
        isTrue("V6 inline sig made using RSA key MUST verify", ops.verify(sig));
    }

    /**
     * A version 4 signature generated using the v6 key.
     * This test verifies that the signature is properly rejected.
     */
    private void testVerificationOfV4SigWithV6KeyFails()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(ARMORED_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        final PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        // v4 timestamp signature containing an IssuerKeyId subpacket
        String V4_SIG = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wloEQBsKABAJEMsYbE8GCaaXBQJmzHd2AAA5wlKWl7C0Dp6dVGDrCFCiISbyL4UE\n" +
                "eYFLRZRnfn25OQmobhAHm2WgY/YOH5bTRLLBSIJiJlstQXMwGQvNNtheQAA=\n" +
                "-----END PGP SIGNATURE-----";

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V4_SIG));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigs = (PGPSignatureList) objFac.nextObject();
        final PGPSignature sig = sigs.get(0);

        isNotNull(testException("MUST NOT verify v4 signature with non-v4 key.", "PGPException",
                new TestExceptionOperation() {
                    public void operation() throws Exception {
                        sig.init(new BcPGPContentVerifierBuilderProvider(), secretKeys.getPublicKey());
                        sig.verify();
                    }
                }));
    }

    public static void main(String[] args)
    {
        runTest(new PGPv6SignatureTest());
    }
}