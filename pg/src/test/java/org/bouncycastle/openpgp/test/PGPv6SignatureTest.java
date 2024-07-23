package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class PGPv6SignatureTest
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
        verifyingInlineSignatureWithSignatureSaltValueMismatchFails();

        verifySignaturesOnEd448X448Key();
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
            fail("Initiating verification of signature with mismatched salt size MUST fail.");
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
            fail("Initiating verification of OPS with mismatched salt size MUST fail.");
        }
        catch (PGPException e)
        {
            // expected.
        }
    }

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
        ByteArrayInputStream bIn = new ByteArrayInputStream(armoredKey.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        Iterator<PGPPublicKey> pubKeys = secretKeys.getPublicKeys();
        PGPPublicKey primaryKey = pubKeys.next();

        Iterator<PGPSignature> directKeySigs = primaryKey.getSignaturesOfType(PGPSignature.DIRECT_KEY);
        while (directKeySigs.hasNext())
        {
            PGPSignature dkSig = directKeySigs.next();
            PGPPublicKey sigKey = getSigningKeyFor(secretKeys, dkSig);
            if (sigKey != null)
            {
                dkSig.init(new BcPGPContentVerifierBuilderProvider(), sigKey);
                isTrue("Direct-Key Signature MUST verify", dkSig.verifyCertification(sigKey));
            }
            else
            {
                System.out.println("Did not find signing key for DK sig");
            }
        }

        Iterator<String> uids = primaryKey.getUserIDs();
        while (uids.hasNext())
        {
            String uid = uids.next();
            Iterator<PGPSignature> uidSigs = primaryKey.getSignaturesForID(uid);
            while (uidSigs.hasNext())
            {
                PGPSignature uidSig = uidSigs.next();
                PGPPublicKey sigKey = getSigningKeyFor(secretKeys, uidSig);
                if (sigKey != null)
                {
                    uidSig.init(new BcPGPContentVerifierBuilderProvider(), sigKey);
                    isTrue("UID Signature for " + uid + " MUST verify",
                        uidSig.verifyCertification(uid, sigKey));
                }
                else
                {
                    System.out.println("Did not find signing key for UID sig for " + uid);
                }
            }
        }

        while (pubKeys.hasNext())
        {
            PGPPublicKey subkey = pubKeys.next();
            Iterator<PGPSignature> bindSigs = subkey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
            while (bindSigs.hasNext())
            {
                PGPSignature bindSig = bindSigs.next();
                PGPPublicKey sigKey = getSigningKeyFor(secretKeys, bindSig);
                if (sigKey != null)
                {
                    bindSig.init(new BcPGPContentVerifierBuilderProvider(), sigKey);
                    isTrue("Subkey binding signature MUST verify",
                        bindSig.verifyCertification(sigKey, subkey));
                }
                else
                {
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
            PGPPublicKey k = pubKeys.next();
            if (k.getKeyID() == sig.getKeyID())
            {
                return k;
            }

            for (SignatureSubpacket p : sig.getHashedSubPackets().getSubpackets(SignatureSubpacketTags.ISSUER_FINGERPRINT))
            {
                IssuerFingerprint fp = (IssuerFingerprint) p;
                if (Arrays.areEqual(k.getFingerprint(), fp.getFingerprint())) {
                    return k;
                }
            }

            for (SignatureSubpacket p : sig.getUnhashedSubPackets().getSubpackets(SignatureSubpacketTags.ISSUER_FINGERPRINT))
            {
                IssuerFingerprint fp = (IssuerFingerprint) p;
                if (Arrays.areEqual(k.getFingerprint(), fp.getFingerprint())) {
                    return k;
                }
            }
        }
        return null;
    }

    public static void main(String[] args)
    {
        runTest(new PGPv6SignatureTest());
    }
}