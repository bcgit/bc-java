package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPV3SignatureGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class PGPSignatureTest
    extends SimpleTest
{
    private static final int[] NO_PREFERENCES = null;
    private static final int[] PREFERRED_SYMMETRIC_ALGORITHMS = new int[] { SymmetricKeyAlgorithmTags.AES_128, SymmetricKeyAlgorithmTags.TRIPLE_DES };
    private static final int[] PREFERRED_HASH_ALGORITHMS = new int[] { HashAlgorithmTags.SHA1, HashAlgorithmTags.SHA256 };
    private static final int[] PREFERRED_COMPRESSION_ALGORITHMS = new int[] { CompressionAlgorithmTags.ZLIB };
    
    private static final int TEST_EXPIRATION_TIME = 10000;
    private static final String TEST_USER_ID = "test user id";
    private static final byte[] TEST_DATA = "hello world!\nhello world!\n".getBytes();
    private static final byte[] TEST_DATA_WITH_CRLF = "hello world!\r\nhello world!\r\n".getBytes();

    byte[] dsaKeyRing = Base64.decode(
          "lQHhBD9HBzURBACzkxRCVGJg5+Ld9DU4Xpnd4LCKgMq7YOY7Gi0EgK92gbaa6+zQ"
        + "oQFqz1tt3QUmpz3YVkm/zLESBBtC1ACIXGggUdFMUr5I87+1Cb6vzefAtGt8N5VV"
        + "1F/MXv1gJz4Bu6HyxL/ncfe71jsNhav0i4yAjf2etWFj53zK6R+Ojg5H6wCgpL9/"
        + "tXVfGP8SqFvyrN/437MlFSUEAIN3V6j/MUllyrZglrtr2+RWIwRrG/ACmrF6hTug"
        + "Ol4cQxaDYNcntXbhlTlJs9MxjTH3xxzylyirCyq7HzGJxZzSt6FTeh1DFYzhJ7Qu"
        + "YR1xrSdA6Y0mUv0ixD5A4nPHjupQ5QCqHGeRfFD/oHzD4zqBnJp/BJ3LvQ66bERJ"
        + "mKl5A/4uj3HoVxpb0vvyENfRqKMmGBISycY4MoH5uWfb23FffsT9r9KL6nJ4syLz"
        + "aRR0gvcbcjkc9Z3epI7gr3jTrb4d8WPxsDbT/W1tv9bG/EHawomLcihtuUU68Uej"
        + "6/wZot1XJqu2nQlku57+M/V2X1y26VKsipolPfja4uyBOOyvbP4DAwIDIBTxWjkC"
        + "GGAWQO2jy9CTvLHJEoTO7moHrp1FxOVpQ8iJHyRqZzLllO26OzgohbiPYz8u9qCu"
        + "lZ9Xn7QzRXJpYyBFY2hpZG5hIChEU0EgVGVzdCBLZXkpIDxlcmljQGJvdW5jeWNh"
        + "c3RsZS5vcmc+iFkEExECABkFAj9HBzUECwcDAgMVAgMDFgIBAh4BAheAAAoJEM0j"
        + "9enEyjRDAlwAnjTjjt57NKIgyym7OTCwzIU3xgFpAJ0VO5m5PfQKmGJRhaewLSZD"
        + "4nXkHg==");
    
    char[]    dsaPass = "hello world".toCharArray();

    byte[]    rsaKeyRing = Base64.decode(
          "lQIEBEBXUNMBBADScQczBibewnbCzCswc/9ut8R0fwlltBRxMW0NMdKJY2LF"
        + "7k2COeLOCIU95loJGV6ulbpDCXEO2Jyq8/qGw1qD3SCZNXxKs3GS8Iyh9Uwd"
        + "VL07nMMYl5NiQRsFB7wOb86+94tYWgvikVA5BRP5y3+O3GItnXnpWSJyREUy"
        + "6WI2QQAGKf4JAwIVmnRs4jtTX2DD05zy2mepEQ8bsqVAKIx7lEwvMVNcvg4Y"
        + "8vFLh9Mf/uNciwL4Se/ehfKQ/AT0JmBZduYMqRU2zhiBmxj4cXUQ0s36ysj7"
        + "fyDngGocDnM3cwPxaTF1ZRBQHSLewP7dqE7M73usFSz8vwD/0xNOHFRLKbsO"
        + "RqDlLA1Cg2Yd0wWPS0o7+qqk9ndqrjjSwMM8ftnzFGjShAdg4Ca7fFkcNePP"
        + "/rrwIH472FuRb7RbWzwXA4+4ZBdl8D4An0dwtfvAO+jCZSrLjmSpxEOveJxY"
        + "GduyR4IA4lemvAG51YHTHd4NXheuEqsIkn1yarwaaj47lFPnxNOElOREMdZb"
        + "nkWQb1jfgqO24imEZgrLMkK9bJfoDnlF4k6r6hZOp5FSFvc5kJB4cVo1QJl4"
        + "pwCSdoU6luwCggrlZhDnkGCSuQUUW45NE7Br22NGqn4/gHs0KCsWbAezApGj"
        + "qYUCfX1bcpPzUMzUlBaD5rz2vPeO58CDtBJ0ZXN0ZXIgPHRlc3RAdGVzdD6I"
        + "sgQTAQIAHAUCQFdQ0wIbAwQLBwMCAxUCAwMWAgECHgECF4AACgkQs8JyyQfH"
        + "97I1QgP8Cd+35maM2cbWV9iVRO+c5456KDi3oIUSNdPf1NQrCAtJqEUhmMSt"
        + "QbdiaFEkPrORISI/2htXruYn0aIpkCfbUheHOu0sef7s6pHmI2kOQPzR+C/j"
        + "8D9QvWsPOOso81KU2axUY8zIer64Uzqc4szMIlLw06c8vea27RfgjBpSCryw"
        + "AgAA");

    char[]    rsaPass = "2002 Buffalo Sabres".toCharArray();

    byte[]    nullPacketsSubKeyBinding = Base64.decode(
            "iDYEGBECAAAAACp9AJ9PlJCrFpi+INwG7z61eku2Wg1HaQCgl33X5Egj+Kf7F9CXIWj2iFCvQDo=");
    
    public void performTest()
        throws Exception
    {
        //
        // RSA tests
        //
        PGPSecretKeyRing pgpPriv = new PGPSecretKeyRing(rsaKeyRing);         
        PGPSecretKey secretKey = pgpPriv.getSecretKey();        
        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(rsaPass, "BC");

        try
        {
            testSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("RSA wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }
        
        try
        {
            testSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("RSA V3 wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }

        //
        // certifications
        //
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, "BC");
        
        sGen.initSign(PGPSignature.KEY_REVOCATION, pgpPrivKey);

        PGPSignature sig = sGen.generateCertification(secretKey.getPublicKey());
        
        sig.initVerify(secretKey.getPublicKey(), "BC");
        
        if (!sig.verifyCertification(secretKey.getPublicKey()))
        {
            fail("revocation verification failed.");
        }
        
        PGPSecretKeyRing pgpDSAPriv = new PGPSecretKeyRing(dsaKeyRing);         
        PGPSecretKey secretDSAKey = pgpDSAPriv.getSecretKey();        
        PGPPrivateKey pgpPrivDSAKey = secretDSAKey.extractPrivateKey(dsaPass, "BC");
        
        sGen = new PGPSignatureGenerator(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, "BC");
        
        sGen.initSign(PGPSignature.SUBKEY_BINDING, pgpPrivDSAKey);

        PGPSignatureSubpacketGenerator    unhashedGen = new PGPSignatureSubpacketGenerator();
        PGPSignatureSubpacketGenerator    hashedGen = new PGPSignatureSubpacketGenerator();
        
        hashedGen.setSignatureExpirationTime(false, TEST_EXPIRATION_TIME);
        hashedGen.setSignerUserID(true, TEST_USER_ID);
        hashedGen.setPreferredCompressionAlgorithms(false, PREFERRED_COMPRESSION_ALGORITHMS);
        hashedGen.setPreferredHashAlgorithms(false, PREFERRED_HASH_ALGORITHMS);
        hashedGen.setPreferredSymmetricAlgorithms(false, PREFERRED_SYMMETRIC_ALGORITHMS);

        sGen.setHashedSubpackets(hashedGen.generate());
        sGen.setUnhashedSubpackets(unhashedGen.generate());
        
        sig = sGen.generateCertification(secretDSAKey.getPublicKey(), secretKey.getPublicKey());

        byte[] sigBytes = sig.getEncoded();
        
        PGPObjectFactory f = new PGPObjectFactory(sigBytes);
        
        sig = ((PGPSignatureList) f.nextObject()).get(0);
        
        sig.initVerify(secretDSAKey.getPublicKey(), "BC");
        
        if (!sig.verifyCertification(secretDSAKey.getPublicKey(), secretKey.getPublicKey()))
        {
            fail("subkey binding verification failed.");
        }
        
        PGPSignatureSubpacketVector hashedPcks = sig.getHashedSubPackets();
        PGPSignatureSubpacketVector unhashedPcks = sig.getUnhashedSubPackets();
        
        if (hashedPcks.size() != 6)
        {
            fail("wrong number of hashed packets found.");
        }

        if (unhashedPcks.size() != 1)
        {
            fail("wrong number of unhashed packets found.");
        }

        if (!hashedPcks.getSignerUserID().equals(TEST_USER_ID))
        {
            fail("test userid not matching");
        }
        
        if (hashedPcks.getSignatureExpirationTime() != TEST_EXPIRATION_TIME)
        {
            fail("test signature expiration time not matching");
        }
        
        if (unhashedPcks.getIssuerKeyID() != secretDSAKey.getKeyID())
        {
            fail("wrong issuer key ID found in certification");
        }
        
        int[] prefAlgs = hashedPcks.getPreferredCompressionAlgorithms();
        preferredAlgorithmCheck("compression", PREFERRED_COMPRESSION_ALGORITHMS, prefAlgs);

        prefAlgs = hashedPcks.getPreferredHashAlgorithms();
        preferredAlgorithmCheck("hash", PREFERRED_HASH_ALGORITHMS, prefAlgs);
        
        prefAlgs = hashedPcks.getPreferredSymmetricAlgorithms();
        preferredAlgorithmCheck("symmetric", PREFERRED_SYMMETRIC_ALGORITHMS, prefAlgs);
        
        int[] criticalHashed = hashedPcks.getCriticalTags();
        
        if (criticalHashed.length != 1)
        {
            fail("wrong number of critical packets found.");
        }
        
        if (criticalHashed[0] != SignatureSubpacketTags.SIGNER_USER_ID)
        {
            fail("wrong critical packet found in tag list.");
        }
        
        //
        // no packets passed
        //
        sGen = new PGPSignatureGenerator(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, "BC");
        
        sGen.initSign(PGPSignature.SUBKEY_BINDING, pgpPrivDSAKey);

        sGen.setHashedSubpackets(null);
        sGen.setUnhashedSubpackets(null);

        sig = sGen.generateCertification(TEST_USER_ID, secretKey.getPublicKey());
        
        sig.initVerify(secretDSAKey.getPublicKey(), "BC");
        
        if (!sig.verifyCertification(TEST_USER_ID, secretKey.getPublicKey()))
        {
            fail("subkey binding verification failed.");
        }
        
        hashedPcks = sig.getHashedSubPackets();
        
        if (hashedPcks.size() != 1)
        {
            fail("found wrong number of hashed packets");
        }
        
        unhashedPcks = sig.getUnhashedSubPackets();
        
        if (unhashedPcks.size() != 1)
        {
            fail("found wrong number of unhashed packets");
        }
        
        try
        {
            sig.verifyCertification(secretKey.getPublicKey());
            
            fail("failed to detect non-key signature.");
        }
        catch (PGPException e)
        {
            // expected
        }
        
        //
        // override hash packets
        //
        sGen = new PGPSignatureGenerator(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, "BC");
        
        sGen.initSign(PGPSignature.SUBKEY_BINDING, pgpPrivDSAKey);

        hashedGen = new PGPSignatureSubpacketGenerator();
        
        hashedGen.setSignatureCreationTime(false, new Date(0L));
        
        sGen.setHashedSubpackets(hashedGen.generate());
        
        sGen.setUnhashedSubpackets(null);

        sig = sGen.generateCertification(TEST_USER_ID, secretKey.getPublicKey());
        
        sig.initVerify(secretDSAKey.getPublicKey(), "BC");
        
        if (!sig.verifyCertification(TEST_USER_ID, secretKey.getPublicKey()))
        {
            fail("subkey binding verification failed.");
        }
        
        hashedPcks = sig.getHashedSubPackets();
        
        if (hashedPcks.size() != 1)
        {
            fail("found wrong number of hashed packets in override test");
        }

        if (!hashedPcks.hasSubpacket(SignatureSubpacketTags.CREATION_TIME))
        {
            fail("hasSubpacket test for creation time failed");
        }
        
        if (!hashedPcks.getSignatureCreationTime().equals(new Date(0L)))
        {
            fail("creation of overriden date failed.");
        }
        
        prefAlgs = hashedPcks.getPreferredCompressionAlgorithms();
        preferredAlgorithmCheck("compression", NO_PREFERENCES, prefAlgs);

        prefAlgs = hashedPcks.getPreferredHashAlgorithms();
        preferredAlgorithmCheck("hash", NO_PREFERENCES, prefAlgs);
        
        prefAlgs = hashedPcks.getPreferredSymmetricAlgorithms();
        preferredAlgorithmCheck("symmetric", NO_PREFERENCES, prefAlgs);
        
        if (hashedPcks.getKeyExpirationTime() != 0)
        {
            fail("unexpected key expiration time found");
        }
        
        if (hashedPcks.getSignatureExpirationTime() != 0)
        {
            fail("unexpected signature expiration time found");
        }
        
        if (hashedPcks.getSignerUserID() != null)
        {
            fail("unexpected signer user ID found");
        }
        
        criticalHashed = hashedPcks.getCriticalTags();
        
        if (criticalHashed.length != 0)
        {
            fail("critical packets found when none expected");
        }
        
        unhashedPcks = sig.getUnhashedSubPackets();
        
        if (unhashedPcks.size() != 1)
        {
            fail("found wrong number of unhashed packets in override test");
        }
        
        //
        // general signatures
        //
        testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256, secretKey.getPublicKey(), pgpPrivKey);
        testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA384, secretKey.getPublicKey(), pgpPrivKey);
        testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA512, secretKey.getPublicKey(), pgpPrivKey);
        testSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);
        testTextSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
        
        //
        // DSA Tests
        //
        pgpPriv = new PGPSecretKeyRing(dsaKeyRing);         
        secretKey = pgpPriv.getSecretKey();        
        pgpPrivKey = secretKey.extractPrivateKey(dsaPass, "BC");
        
        try
        {
            testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("DSA wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }
        
        try
        {
            testSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("DSA V3 wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }
        
        testSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);
        testSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);
        testTextSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
        
        // special cases
        //
        testMissingSubpackets(nullPacketsSubKeyBinding);
        
        testMissingSubpackets(generateV3BinarySig(pgpPrivKey, PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1));

        // keyflags
        testKeyFlagsValues();
    }

    private void testKeyFlagsValues()
    {
        checkValue(KeyFlags.CERTIFY_OTHER, 0x01);
        checkValue(KeyFlags.SIGN_DATA, 0x02);
        checkValue(KeyFlags.ENCRYPT_COMMS, 0x04);
        checkValue(KeyFlags.ENCRYPT_STORAGE, 0x08);
        checkValue(KeyFlags.SPLIT, 0x10);
        checkValue(KeyFlags.AUTHENTICATION, 0x20);
        checkValue(KeyFlags.SHARED, 0x80);

        // yes this actually happens
        checkValue(new byte[] { 4, 0, 0, 0 }, 0x04);
        checkValue(new byte[] { 4, 0, 0 }, 0x04);
        checkValue(new byte[] { 4, 0 }, 0x04);
        checkValue(new byte[] { 4 }, 0x04);
    }

    private void checkValue(int flag, int value)
    {
        KeyFlags f = new KeyFlags(true, flag);

        if (f.getFlags() != value)
        {
            fail("flag value mismatch");
        }
    }

    private void checkValue(byte[] flag, int value)
    {
        KeyFlags f = new KeyFlags(true, flag);

        if (f.getFlags() != value)
        {
            fail("flag value mismatch");
        }
    }

    private void testMissingSubpackets(byte[] signature) 
        throws IOException
    {
        PGPObjectFactory f = new PGPObjectFactory(signature);
        Object           obj = f.nextObject();
        
        while (!(obj instanceof PGPSignatureList))
        {
            obj = f.nextObject();
            if (obj instanceof PGPLiteralData)
            {
                InputStream in = ((PGPLiteralData)obj).getDataStream();
                Streams.drain(in);
            }
        }
        
        PGPSignature     sig = ((PGPSignatureList)obj).get(0);
        
        if (sig.getVersion() > 3)
        {
            PGPSignatureSubpacketVector v = sig.getHashedSubPackets();
            
            if (v.getKeyExpirationTime() != 0)
            {
                fail("key expiration time not zero for missing subpackets");
            }

            if (!sig.hasSubpackets())
            {
                fail("hasSubpackets() returns false with packets");
            }
        }
        else
        {
            if (sig.getHashedSubPackets() != null)
            {
                fail("hashed sub packets found when none expected");
            }
            if (sig.getUnhashedSubPackets() != null)
            {
                fail("unhashed sub packets found when none expected");
            }

            if (sig.hasSubpackets())
            {
                fail("hasSubpackets() returns true with no packets");
            }
        }
    }

    private void preferredAlgorithmCheck(
        String type,
        int[] expected,  
        int[] prefAlgs)
    {
        if (expected == null)
        {
            if (prefAlgs != null)
            {
                fail("preferences for " + type + " found when none expected");
            }
        }
        else
        {   
            if (prefAlgs.length != expected.length)
            {
                fail("wrong number of preferred " + type + " algorithms found");
            }
            
            for (int i = 0; i != expected.length; i++)
            {
                if (expected[i] != prefAlgs[i])
                {
                    fail("wrong algorithm found for " + type + ": expected " + expected[i] + " got " + prefAlgs);
                }
            }
        }
    }

    private void testSig(
        int           encAlgorithm,
        int           hashAlgorithm,
        PGPPublicKey  pubKey,
        PGPPrivateKey privKey)
        throws Exception
    {            
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ByteArrayInputStream  testIn = new ByteArrayInputStream(TEST_DATA);
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(encAlgorithm, hashAlgorithm, "BC");
        
        sGen.initSign(PGPSignature.BINARY_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);
    
        PGPLiteralDataGenerator    lGen = new PGPLiteralDataGenerator();
        OutputStream               lOut = lGen.open(
            new UncloseableOutputStream(bOut),
            PGPLiteralData.BINARY,
            "_CONSOLE",
            TEST_DATA.length * 2,
            new Date());

        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(TEST_DATA);
        sGen.update(TEST_DATA);
        
        lGen.close();
    
        sGen.generate().encode(bOut);
    
        verifySignature(bOut.toByteArray(), hashAlgorithm, pubKey, TEST_DATA);
    }
    
    private void testTextSig(
        int            encAlgorithm,
        int            hashAlgorithm,
        PGPPublicKey   pubKey,
        PGPPrivateKey  privKey,
        byte[]         data,
        byte[]         canonicalData)
        throws Exception
    {            
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(encAlgorithm, HashAlgorithmTags.SHA1, "BC");  
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ByteArrayInputStream  testIn = new ByteArrayInputStream(data);
        Date                  creationTime = new Date();
        
        sGen.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator    lGen = new PGPLiteralDataGenerator();
        OutputStream               lOut = lGen.open(
            new UncloseableOutputStream(bOut),
            PGPLiteralData.TEXT,
            "_CONSOLE",
            data.length * 2,
            creationTime);

        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(data);
        sGen.update(data);
        
        lGen.close();
    
        PGPSignature sig = sGen.generate();

        if (sig.getCreationTime().getTime() == 0)
        {
            fail("creation time not set in v4 signature");
        }

        sig.encode(bOut);
    
        verifySignature(bOut.toByteArray(), hashAlgorithm, pubKey, canonicalData);
    }
    
    private void testSigV3(
        int           encAlgorithm,
        int           hashAlgorithm,
        PGPPublicKey  pubKey,
        PGPPrivateKey privKey)
        throws Exception
    {            
        byte[] bytes = generateV3BinarySig(privKey, encAlgorithm, hashAlgorithm);
    
        verifySignature(bytes, hashAlgorithm, pubKey, TEST_DATA);
    }

    private byte[] generateV3BinarySig(PGPPrivateKey privKey, int encAlgorithm, int hashAlgorithm) 
        throws Exception
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ByteArrayInputStream    testIn = new ByteArrayInputStream(TEST_DATA);
        PGPV3SignatureGenerator sGen = new PGPV3SignatureGenerator(encAlgorithm, hashAlgorithm, "BC");
        
        sGen.initSign(PGPSignature.BINARY_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);
    
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream            lOut = lGen.open(
            new UncloseableOutputStream(bOut),
            PGPLiteralData.BINARY,
            "_CONSOLE",
            TEST_DATA.length * 2,
            new Date());

        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(TEST_DATA);
        sGen.update(TEST_DATA);
        
        lGen.close();
    
        sGen.generate().encode(bOut);
        
        return bOut.toByteArray();
    }
    
    private void testTextSigV3(
        int            encAlgorithm,
        int            hashAlgorithm,
        PGPPublicKey   pubKey,
        PGPPrivateKey  privKey,
        byte[]         data,
        byte[]         canonicalData)
        throws Exception
    {            
        PGPV3SignatureGenerator sGen = new PGPV3SignatureGenerator(encAlgorithm, HashAlgorithmTags.SHA1, "BC");
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ByteArrayInputStream    testIn = new ByteArrayInputStream(data);
        
        sGen.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream            lOut = lGen.open(
            new UncloseableOutputStream(bOut),
            PGPLiteralData.TEXT,
            "_CONSOLE",
            data.length * 2,
            new Date());

        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(data);
        sGen.update(data);
        
        lGen.close();
    
        PGPSignature sig = sGen.generate();

        if (sig.getCreationTime().getTime() == 0)
        {
            fail("creation time not set in v3 signature");
        }

        sig.encode(bOut);

        verifySignature(bOut.toByteArray(), hashAlgorithm, pubKey, canonicalData);
    }
    
    private void verifySignature(
        byte[] encodedSig, 
        int hashAlgorithm, 
        PGPPublicKey pubKey,  
        byte[] original) 
        throws IOException, PGPException, NoSuchProviderException, SignatureException
    {
        PGPObjectFactory        pgpFact = new PGPObjectFactory(encodedSig);
        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature     ops = p1.get(0);
        PGPLiteralData          p2 = (PGPLiteralData)pgpFact.nextObject();
        InputStream             dIn = p2.getInputStream();
    
        ops.initVerify(pubKey, "BC");
        
        int ch;

        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
        }
    
        PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = p3.get(0);

        Date creationTime = sig.getCreationTime();
        Date now = new Date();

        // Check creationTime is recent
        if (creationTime.after(now)
            || creationTime.before(new Date(now.getTime() - 10 * 60 * 1000)))
        {
            fail("bad creation time in signature: " + creationTime);
        }

        if (sig.getKeyID() != pubKey.getKeyID())
        {
            fail("key id mismatch in signature");
        }
        
        if (!ops.verify(sig))
        {
            fail("Failed generated signature check - " + hashAlgorithm);
        }
        
        sig.initVerify(pubKey, "BC");
        
        for (int i = 0; i != original.length; i++)
        {
            sig.update(original[i]);
        }
        
        sig.update(original);
        
        if (!sig.verify())
        {
            fail("Failed generated signature check against original data");
        }
    }
    
    public String getName()
    {
        return "PGPSignatureTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPSignatureTest());
    }
}
