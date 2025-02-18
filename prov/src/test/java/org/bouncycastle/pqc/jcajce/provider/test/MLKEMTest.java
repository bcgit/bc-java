package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * KEM tests for MLKEM with the BC provider.
 */
public class MLKEMTest
    extends TestCase
{
    static private final String[] names = new String[]{
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024"
    };
    
    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testParametersAndParamSpecs()
        throws Exception
    {
        MLKEMParameters mlKemParameters[] = new MLKEMParameters[]
            {
                MLKEMParameters.ml_kem_512,
                MLKEMParameters.ml_kem_768,
                MLKEMParameters.ml_kem_1024
            };

        for (int i = 0; i != names.length; i++)
        {
            assertEquals(names[i], MLKEMParameterSpec.fromName(mlKemParameters[i].getName()).getName());
        }

        for (int i = 0; i != names.length; i++)
        {
            assertEquals(names[i], MLKEMParameterSpec.fromName(names[i]).getName());
        }
    }
    
    public void testKeyFactory()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("ML-KEM", "BC");
        KeyPairGenerator kpGen512 = KeyPairGenerator.getInstance("ML-KEM-512");
        KeyPair kp512 = kpGen512.generateKeyPair();
        KeyPairGenerator kpGen768 = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair kp768 = kpGen768.generateKeyPair();
        KeyPairGenerator kpGen1024 = KeyPairGenerator.getInstance("ML-KEM-1024");
        KeyPair kp1024 = kpGen1024.generateKeyPair();

        tryKeyFact(KeyFactory.getInstance("ML-KEM-512", "BC"), kp512, kp768, "2.16.840.1.101.3.4.4.2");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_alg_ml_kem_512.toString(), "BC"), kp512, kp768, "2.16.840.1.101.3.4.4.2");
        tryKeyFact(KeyFactory.getInstance("ML-KEM-768", "BC"), kp768, kp512, "2.16.840.1.101.3.4.4.1");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_alg_ml_kem_768.toString(), "BC"), kp768, kp512, "2.16.840.1.101.3.4.4.1");
        tryKeyFact(KeyFactory.getInstance("ML-KEM-1024", "BC"), kp1024, kp768, "2.16.840.1.101.3.4.4.2");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_alg_ml_kem_1024.toString(), "BC"), kp1024, kp768, "2.16.840.1.101.3.4.4.2");
    }

    private void tryKeyFact(KeyFactory kFact, KeyPair kpValid, KeyPair kpInvalid, String oid)
        throws Exception
    {
        kFact.generatePrivate(new PKCS8EncodedKeySpec(kpValid.getPrivate().getEncoded()));
        kFact.generatePublic(new X509EncodedKeySpec(kpValid.getPublic().getEncoded()));

        try
        {
            kFact.generatePrivate(new PKCS8EncodedKeySpec(kpInvalid.getPrivate().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
        try
        {
            kFact.generatePublic(new X509EncodedKeySpec(kpInvalid.getPublic().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
    }

    public void testDefaultPrivateKeyEncoding()
        throws Exception
    {
        KeyPairGenerator kpGen512 = KeyPairGenerator.getInstance("ML-KEM-512", "BC");

        byte[] seed = Hex.decode("000102030405060708090a0b0c0d0e0f"
            + "100102030405060708090a0b0c0d0e0f"
            + "200102030405060708090a0b0c0d0e0f"
            + "300102030405060708090a0b0c0d0e0f");
        kpGen512.initialize(MLKEMParameterSpec.ml_kem_512, new FixedSecureRandom(seed));
        KeyPair kp512 = kpGen512.generateKeyPair();

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp512.getPrivate().getEncoded());
        ASN1OctetString seq = ASN1OctetString.getInstance(ASN1Sequence.getInstance(privInfo.getPrivateKey().getOctets()).getObjectAt(0));

        assertTrue(Arrays.areEqual(seq.getOctets(), seed));

        ASN1OctetString privData = ASN1OctetString.getInstance((ASN1TaggedObject)ASN1Sequence.getInstance(privInfo.getPrivateKey().getOctets()).getObjectAt(1), false);

        assertTrue(Arrays.areEqual(privData.getOctets(), ((MLKEMPrivateKey)kp512.getPrivate()).getPrivateData()));
    }

    public void testSeedPrivateKeyEncoding()
        throws Exception
    {
        KeyPairGenerator kpGen512 = KeyPairGenerator.getInstance("ML-KEM-512", "BC");

        byte[] seed = Hex.decode("000102030405060708090a0b0c0d0e0f"
            + "100102030405060708090a0b0c0d0e0f"
            + "200102030405060708090a0b0c0d0e0f"
            + "300102030405060708090a0b0c0d0e0f");
        kpGen512.initialize(MLKEMParameterSpec.ml_kem_512, new FixedSecureRandom(seed));
        KeyPair kp512 = kpGen512.generateKeyPair();
        Security.setProperty("org.bouncycastle.mlkem.seedOnly", "true");

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp512.getPrivate().getEncoded());

        Security.setProperty("org.bouncycastle.mlkem.seedOnly", "false");
        ASN1OctetString k = privInfo.getPrivateKey();

        assertTrue(Arrays.areEqual(k.getOctets(), seed));
    }

    public void testPrivateKeyRecoding()
        throws Exception
    {
        byte[] mlkem512_sequence = Base64.decode("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");
        byte[] mlkem512_seed_only = Base64.decode("MFICAQAwCwYJYIZIAWUDBAQBBEAAAQIDBAUGBwgJCgsMDQ4PEAECAwQFBgcICQoLDA0ODyABAgMEBQYHCAkKCwwNDg8wAQIDBAUGBwgJCgsMDQ4P");
        byte[] mlkem512_wrap_seed_only = Base64.decode("MFQCAQAwCwYJYIZIAWUDBAQBBEIEQAABAgMEBQYHCAkKCwwNDg8QAQIDBAUGBwgJCgsMDQ4PIAECAwQFBgcICQoLDA0ODzABAgMEBQYHCAkKCwwNDg8=");
        byte[] mlKem512_expanded_only = Base64.decode("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");
        byte[] mlKem512_wrap_expanded_only = Base64.decode("MIIGeAIBADALBglghkgBZQMEBAEEggZkBIIGYFgheh/clZvpxx5ac9Xzi/Dom89hjrl0g0IcF60pw62mtn2AdC8Vddk7KexYIAdcZryIPhgVyaCXCegDw7gwqhP0bVuXkmcCiyP3KnrmzWm5Uu0gkEjka2YjblZKBoD4pE/Yc1A4bw4XRO7bg/nBdVH6RAhmThQxX2inhbnyZV/5HCAMBY4Fzj6iawYlHdwVLG9hvNZMciR3xDg2rld6efHQFkXluFn8M5vAj/jlzALFImU5RwsycW2lxT8AgWqJHP/FwXehVDgSxwI8W1USr7k0EvCRCSxUx76mLXoYpOuoRHTVCQX0qURhWpURY716fGnBV5pblU0LDunqEy+aTtJ2dX4XrX9ESoM3iNOxtMSIXq6sZZ9XcI+1bTOlrFulsWXBR5AUDFhYkVIrcSdUCG6mP9T6OrgRKf2GDjxKHu6jMNocb2nTRH+yokT6ukfqMQzMJ7YXsfeDu/GTaAx4jOT3VOFio/BJK8kqOPbkvnf2FJ8cRmW0kmPrs02GOw/sO83Gqa9LIJplCB7WBFOlsZgjBQPDZgAcksNMToSWgwbJORFitWmapDPnqm4WH0cCKRb6ymqQIvOouowGnXMJvAEkY5smZkXwmJHrxvJIrFUIOOExWz+kWKF6BR81yNwYLiQpmxgUu2BUn8B3CIjsm7iVkC6sSGWZD3c5RppzK9ubopmwccsyAeGcOx7GXxhBkN8XQLAkYRbJEMNFwxyFVmfSGTf6aH6lJTYaqnhggukWkZIAzHayxPGwXgfFlLdEslyoAmXlyQbISmt3YWXjqtcljbeYQf62Sg4LM6j5sL/oYmcVEYOlVCTxKIl2gLGxwWSlkTssJu1nivIIXbMms4RhWyTHSoQDkmCgYFiAQnFAR2TCxIbZt4DSx3cxseA7QuHRpiR8TEYRaB+XF/wEZTvkXCrXjWU3Mk/oZUiIMlP8AYMcwYSMLFZpDGIrjxp5qhABdPiyO/Vaq0wyRZnQWBibHUoTlfBMuCRrpZqETd6Mjrb7Dz6SfEH5dMYCS5+jbPOynCPzFGl7YpTKXmMMUtQMBZ7yWRswyodRsU7Sg/O4k8xKyIIldABaI7BGefQJL4xphcNYz74UiF7BfdNBDHPDtqFgKyhyGM11i9gJnw5ppoxcU1uCHOcckHo5Im4qJWx4QG9EWGHrCNWZlJ1wo8ogUs/wqYCMhSI6lVwDsRpsuVyXTKGwyW4YdMZ1d7srTRl7kYmKo52kE81RKWzVGF2wHVaBbh38DCn8unhyAV6CyRZ6XSzhGJ2Iq3gmL9ZqxmI1rB/TGOGLNe77yHBUomv0XPlbR/QiZNm6oBFaitk7FeioERGiYAwZo9AUafKLqzv2ABTLJcS3C0A6qyrQOCYRnAM4bGI6c0JQV5Y0paphSlpowiAURaxWjBvsb++mAWqoftGhECjlU9icDcgAxt0qJ4aFA6L6PifVJWhpY8JnmgEAqLkGQwlxC4K3iqRzhWjCu0aUBzY7Zb/hblfpO1p7nTkbPTXXvdisNd0kUrpZkLWqNUhyX9FUXL7kLt3jMyy7I5bhJSqhKbw2V/woO+l4BKbWGhKpTEDUmun4d9G3PhoaMhURsd85N872xq7axFojyGnAjHkCjJonjfGqY62oAImbBnaTArH8atcQCa2hweHDBkosd2TqfK4irpojuBEMA4bSRruDV2ywuOfSZKmhD9R0wP4zacIiEQbBxN3ZTmhRO4iZPs56zF83BvtXxwF4Q2rcDxIswC7qcoU8QIibAls8XLShW86Ls28HLlwCqiW5XTXUbMfhEmroKDfkCi5hCTiZaY1ihSDkROHWll6aAs+Fj8NQAwk4g0N1s0z0J+OrZYAwxcE8etHiZPggJ+PEPnmDN1ukgwraiymIFIy5SXGpHSjJiiVXSC9QOuoLR94wP6Cbq4zRjWhyvmTSg5vTcSq1kPT5pgQIh7DyqiKLC0eLGeqADQuJrVRyt5WZmM/SyP3oyHy4He2sNSDQbqTjz6Rpq0KgOC3BoHdJjAlUSysRKjwUbkw2iwQCPB3SVMLIMCNxqx9WZALDRwYZr1HUjY4nKZTqFh3DWIvVOBWZCInwYx1IBlDVIZsODJH9yH3mLSaC7Y6WDiI0N8hR/M83RCgWO+CCx0/gUlompAMgAQIDBAUGBwgJCgsMDQ4PMAECAwQFBgcICQoLDA0ODw==");
        byte[] mlkem512_seed_with_pub_key = Base64.decode("MIIDdwIBATALBglghkgBZQMEBAEEQAABAgMEBQYHCAkKCwwNDg8QAQIDBAUGBwgJCgsMDQ4PIAECAwQFBgcICQoLDA0ODzABAgMEBQYHCAkKCwwNDg+BggMhAPOynCPzFGl7YpTKXmMMUtQMBZ7yWRswyodRsU7Sg/O4k8xKyIIldABaI7BGefQJL4xphcNYz74UiF7BfdNBDHPDtqFgKyhyGM11i9gJnw5ppoxcU1uCHOcckHo5Im4qJWx4QG9EWGHrCNWZlJ1wo8ogUs/wqYCMhSI6lVwDsRpsuVyXTKGwyW4YdMZ1d7srTRl7kYmKo52kE81RKWzVGF2wHVaBbh38DCn8unhyAV6CyRZ6XSzhGJ2Iq3gmL9ZqxmI1rB/TGOGLNe77yHBUomv0XPlbR/QiZNm6oBFaitk7FeioERGiYAwZo9AUafKLqzv2ABTLJcS3C0A6qyrQOCYRnAM4bGI6c0JQV5Y0paphSlpowiAURaxWjBvsb++mAWqoftGhECjlU9icDcgAxt0qJ4aFA6L6PifVJWhpY8JnmgEAqLkGQwlxC4K3iqRzhWjCu0aUBzY7Zb/hblfpO1p7nTkbPTXXvdisNd0kUrpZkLWqNUhyX9FUXL7kLt3jMyy7I5bhJSqhKbw2V/woO+l4BKbWGhKpTEDUmun4d9G3PhoaMhURsd85N872xq7axFojyGnAjHkCjJonjfGqY62oAImbBnaTArH8atcQCa2hweHDBkosd2TqfK4irpojuBEMA4bSRruDV2ywuOfSZKmhD9R0wP4zacIiEQbBxN3ZTmhRO4iZPs56zF83BvtXxwF4Q2rcDxIswC7qcoU8QIibAls8XLShW86Ls28HLlwCqiW5XTXUbMfhEmroKDfkCi5hCTiZaY1ihSDkROHWll6aAs+Fj8NQAwk4g0N1s0z0J+OrZYAwxcE8etHiZPggJ+PEPnmDN1ukgwraiymIFIy5SXGpHSjJiiVXSC9QOuoLR94wP6Cbq4zRjWhyvmTSg5vTcSq1kPT5pgQIh7DyqiKLC0eLGeqADQuJrVRyt5WZmM/SyP3oyHy4He2sNSDQbqTjz6Rpq0KgOC3BoHdJjAlUSysRKjwUbkw2iwQCPB3SVMLIMCNxqx9WZALDRwYZr1HUjY4nKZTqFh3DWIvVOBWZCInwYx1IBlDVIZsODJH9");

        KeyFactory kFact = KeyFactory.getInstance("ML-KEM", "BC");

        checkEncodeRecode(kFact, mlkem512_sequence);
        checkEncodeRecode(kFact, mlkem512_seed_only);
        checkEncodeRecode(kFact, mlkem512_wrap_seed_only);
        checkEncodeRecode(kFact, mlKem512_expanded_only);
        checkEncodeRecode(kFact, mlKem512_wrap_expanded_only);
        checkEncodeRecode(kFact, mlkem512_seed_with_pub_key);
    }

    private void checkEncodeRecode(KeyFactory kFact, byte[] encoding)
        throws Exception
    {
        PrivateKey key = kFact.generatePrivate(new PKCS8EncodedKeySpec(encoding));

        assertTrue(Arrays.areEqual(encoding, key.getEncoded()));
    }

    public void testBasicKEMCamellia()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        kpg.generateKeyPair().getPrivate().getEncoded();
        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("Camellia", 128).withNoKdf().build());
        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("Camellia-KWP", 128).withNoKdf().build());
    }

    public void testBasicKEMSEED()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("SEED", 128).build());
    }

    public void testBasicKEMARIA()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("ARIA", 256).build());
        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("ARIA-KWP", 256).build());
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KTSParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BC");

        byte[] keyBytes;
        if (ktsParameterSpec.getKeyAlgorithmName().endsWith("KWP"))
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0faa");
        }
        else
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        }
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        w1.init(Cipher.WRAP_MODE, kp.getPublic(), ktsParameterSpec);

        byte[] data = w1.wrap(key);

        Cipher w2 = Cipher.getInstance(algorithm, "BC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("ML-KEM", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES", 128), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(16, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES", 128));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testGenerateAES256()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_1024, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("ML-KEM", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        doTestRestrictedKeyPairGen(MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyPairGen(MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyPairGen(MLKEMParameterSpec.ml_kem_1024, MLKEMParameterSpec.ml_kem_512);
    }

    private void doTestRestrictedKeyPairGen(MLKEMParameterSpec spec, MLKEMParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        try
        {
            kpg.initialize(altSpec, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key pair generator locked to " + spec.getName(), e.getMessage());
        }
    }

    public void testRestrictedKeyGen()
        throws Exception
    {
        doTestRestrictedKeyGen(MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyGen(MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyGen(MLKEMParameterSpec.ml_kem_1024, MLKEMParameterSpec.ml_kem_512);
    }

    private void doTestRestrictedKeyGen(MLKEMParameterSpec spec, MLKEMParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        KeyGenerator keyGen = KeyGenerator.getInstance(spec.getName(), "BC");

        assertEquals(spec.getName(), keyGen.getAlgorithm());

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));

        kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");

        kpg.initialize(altSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to " + spec.getName(), e.getMessage());
        }

        try
        {
            keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to " + spec.getName(), e.getMessage());
        }
    }

    public void testRestrictedCipher()
        throws Exception
    {
        doTestRestrictedCipher(MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_1024, new byte[16]);
        doTestRestrictedCipher(MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024, new byte[24]);
        doTestRestrictedCipher(MLKEMParameterSpec.ml_kem_1024, MLKEMParameterSpec.ml_kem_512, new byte[32]);
    }

    private void doTestRestrictedCipher(MLKEMParameterSpec spec, MLKEMParameterSpec altSpec, byte[] keyBytes)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        Cipher cipher = Cipher.getInstance(spec.getName(), "BC");

        assertEquals(spec.getName(), cipher.getAlgorithm());

        cipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());

        byte[] wrapBytes = cipher.wrap(new SecretKeySpec(keyBytes, "AES"));

        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());

        Key unwrapKey = cipher.unwrap(wrapBytes, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, unwrapKey.getEncoded()));

        kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");

        kpg.initialize(altSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("cipher locked to " + spec.getName(), e.getMessage());
        }

        try
        {
            cipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("cipher locked to " + spec.getName(), e.getMessage());
        }
    }
}
