package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesConstraints;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.constraints.LegacyBitsOfSecurityConstraint;
import org.bouncycastle.crypto.constraints.QuantumVulnerableConstraint;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.HSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The post-quantum algorithms report to the constraints framework with the classical strength of
 * their parameter set, and the quantum-vulnerable constraint applies the NIST IR 8547 timetable
 * to the classical public-key algorithms and leaves the post-quantum ones alone.
 */
public class PQCConstraintsTest
    extends SimpleTest
{
    private static final Date PAST = new Date(0L);
    private static final Date FAR_FUTURE = new Date(Long.MAX_VALUE / 2);

    private final SecureRandom random = new SecureRandom();

    public String getName()
    {
        return "PQCConstraints";
    }

    public void performTest()
        throws Exception
    {
        try
        {
            testKeyGenerationStrength();
            testKemAndSignerStrength();
            testStrictPolicyAcceptsStrongSets();
            testServiceNames();
            testQuantumVulnerableSignal();
            testQuantumVulnerableConstraint();
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
        }
    }

    private void testKeyGenerationStrength()
    {
        // built up front: constructing a SHA-256 digest under a 192-bit constraint is itself refused
        XMSSParameters xmssParams = new XMSSParameters(10, new SHA256Digest());
        XMSSMTParameters xmssmtParams = new XMSSMTParameters(20, 2, new SHA256Digest());

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(192));

        MLKEMKeyPairGenerator mlkemGen = new MLKEMKeyPairGenerator();
        expectRefused(mlkemGen, new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_512), 128);
        mlkemGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));

        MLDSAKeyPairGenerator mldsaGen = new MLDSAKeyPairGenerator();
        expectRefused(mldsaGen, new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_44), 128);
        mldsaGen.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65));

        SLHDSAKeyPairGenerator slhdsaGen = new SLHDSAKeyPairGenerator();
        expectRefused(slhdsaGen, new SLHDSAKeyGenerationParameters(random, SLHDSAParameters.shake_128f), 128);
        slhdsaGen.init(new SLHDSAKeyGenerationParameters(random, SLHDSAParameters.sha2_192f));

        FalconKeyPairGenerator falconGen = new FalconKeyPairGenerator();
        expectRefused(falconGen, new FalconKeyGenerationParameters(random, FalconParameters.falcon_512), 128);
        falconGen.init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_1024));

        HQCKeyPairGenerator hqcGen = new HQCKeyPairGenerator();
        expectRefused(hqcGen, new HQCKeyGenerationParameters(random, HQCParameters.hqc128), 128);
        hqcGen.init(new HQCKeyGenerationParameters(random, HQCParameters.hqc192));

        LMSParameters lms192 = new LMSParameters(LMSigParameters.lms_sha256_n24_h5, LMOtsParameters.sha256_n24_w4);
        LMSParameters lms256 = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);

        new LMSKeyPairGenerator().init(new LMSKeyGenerationParameters(lms192, random));
        new HSSKeyPairGenerator().init(new HSSKeyGenerationParameters(new LMSParameters[]{ lms256, lms192 }, random));
        new XMSSKeyPairGenerator().init(new XMSSKeyGenerationParameters(xmssParams, random));
        new XMSSMTKeyPairGenerator().init(new XMSSMTKeyGenerationParameters(xmssmtParams, random));

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        expectRefused(new LMSKeyPairGenerator(), new LMSKeyGenerationParameters(lms192, random), 192);
        new LMSKeyPairGenerator().init(new LMSKeyGenerationParameters(lms256, random));
        // an HSS hierarchy is as strong as its weakest level
        expectRefused(new HSSKeyPairGenerator(), new HSSKeyGenerationParameters(new LMSParameters[]{ lms256, lms192 }, random), 192);
        new HSSKeyPairGenerator().init(new HSSKeyGenerationParameters(new LMSParameters[]{ lms256, lms256 }, random));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testKemAndSignerStrength()
    {
        MLKEMKeyPairGenerator mlkemGen = new MLKEMKeyPairGenerator();
        mlkemGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_512));
        AsymmetricCipherKeyPair mlkemKp = mlkemGen.generateKeyPair();

        MLDSAKeyPairGenerator mldsaGen = new MLDSAKeyPairGenerator();
        mldsaGen.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_44));
        AsymmetricCipherKeyPair mldsaKp = mldsaGen.generateKeyPair();

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(192));

        try
        {
            new MLKEMGenerator(random).generateEncapsulated(mlkemKp.getPublic());
            fail("ML-KEM-512 encapsulation not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }
        try
        {
            new MLKEMExtractor((MLKEMPrivateKeyParameters)mlkemKp.getPrivate());
            fail("ML-KEM-512 extractor not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }
        try
        {
            new MLDSASigner().init(true, mldsaKp.getPrivate());
            fail("ML-DSA-44 signing not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }

        // legacy use: verification is allowed at the lower level, signing is not
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192, 128));

        new MLDSASigner().init(false, mldsaKp.getPublic());
        try
        {
            new MLDSASigner().init(true, mldsaKp.getPrivate());
            fail("ML-DSA-44 signing not refused under legacy constraint");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }

        // an exception for the service name lets it through
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(192, Collections.singleton("ML-DSA")));

        new MLDSASigner().init(true, mldsaKp.getPrivate());

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    /**
     * The hash functions the engines build internally carry the INTERNAL purpose and are not
     * checked on their own, so a strict policy sees the strength of the parameter set rather than
     * the 128 bits of the SHAKE128 or SHA-256 inside it, and the category 5 sets work under a
     * 256-bit constraint.
     */
    private void testStrictPolicyAcceptsStrongSets()
        throws Exception
    {
        byte[] msg = new byte[]{ 1, 2, 3, 4, 5 };
        XMSSParameters xmssParams = new XMSSParameters(4, new SHA256Digest());
        LMSParameters lms256 = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        MLDSAKeyPairGenerator mldsaGen = new MLDSAKeyPairGenerator();
        mldsaGen.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_87));
        AsymmetricCipherKeyPair mldsaKp = mldsaGen.generateKeyPair();
        MLDSASigner mldsaSigner = new MLDSASigner();
        mldsaSigner.init(true, mldsaKp.getPrivate());
        mldsaSigner.update(msg, 0, msg.length);
        byte[] sig = mldsaSigner.generateSignature();
        mldsaSigner.init(false, mldsaKp.getPublic());
        mldsaSigner.update(msg, 0, msg.length);
        isTrue("ML-DSA-87", mldsaSigner.verifySignature(sig));

        MLKEMKeyPairGenerator mlkemGen = new MLKEMKeyPairGenerator();
        mlkemGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_1024));
        AsymmetricCipherKeyPair mlkemKp = mlkemGen.generateKeyPair();
        org.bouncycastle.crypto.SecretWithEncapsulation enc = new MLKEMGenerator(random).generateEncapsulated(mlkemKp.getPublic());
        isTrue("ML-KEM-1024", org.bouncycastle.util.Arrays.areEqual(enc.getSecret(),
            new MLKEMExtractor((MLKEMPrivateKeyParameters)mlkemKp.getPrivate()).extractSecret(enc.getEncapsulation())));

        SLHDSAKeyPairGenerator slhdsaGen = new SLHDSAKeyPairGenerator();
        slhdsaGen.init(new SLHDSAKeyGenerationParameters(random, SLHDSAParameters.sha2_256f));
        AsymmetricCipherKeyPair slhdsaKp = slhdsaGen.generateKeyPair();
        org.bouncycastle.crypto.signers.SLHDSASigner slhdsaSigner = new org.bouncycastle.crypto.signers.SLHDSASigner();
        slhdsaSigner.init(true, slhdsaKp.getPrivate());
        sig = slhdsaSigner.generateSignature(msg);
        slhdsaSigner.init(false, slhdsaKp.getPublic());
        isTrue("SLH-DSA-SHA2-256f", slhdsaSigner.verifySignature(msg, sig));

        LMSKeyPairGenerator lmsGen = new LMSKeyPairGenerator();
        lmsGen.init(new LMSKeyGenerationParameters(lms256, random));
        AsymmetricCipherKeyPair lmsKp = lmsGen.generateKeyPair();
        org.bouncycastle.crypto.signers.LMSSigner lmsSigner = new org.bouncycastle.crypto.signers.LMSSigner();
        lmsSigner.init(true, lmsKp.getPrivate());
        sig = lmsSigner.generateSignature(msg);
        lmsSigner.init(false, lmsKp.getPublic());
        isTrue("LMS SHA-256", lmsSigner.verifySignature(msg, sig));

        XMSSKeyPairGenerator xmssGen = new XMSSKeyPairGenerator();
        xmssGen.init(new XMSSKeyGenerationParameters(xmssParams, random));
        AsymmetricCipherKeyPair xmssKp = xmssGen.generateKeyPair();
        org.bouncycastle.crypto.signers.XMSSSigner xmssSigner = new org.bouncycastle.crypto.signers.XMSSSigner();
        xmssSigner.init(true, xmssKp.getPrivate());
        xmssSigner.update(msg, 0, msg.length);
        sig = xmssSigner.generateSignature();
        xmssSigner.init(false, xmssKp.getPublic());
        xmssSigner.update(msg, 0, msg.length);
        isTrue("XMSS SHA-256", xmssSigner.verifySignature(sig));

        HQCKeyPairGenerator hqcGen = new HQCKeyPairGenerator();
        hqcGen.init(new HQCKeyGenerationParameters(random, HQCParameters.hqc256));
        AsymmetricCipherKeyPair hqcKp = hqcGen.generateKeyPair();
        enc = new org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator(random).generateEncapsulated(hqcKp.getPublic());
        isTrue("HQC-256", org.bouncycastle.util.Arrays.areEqual(enc.getSecret(),
            new org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor((org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters)hqcKp.getPrivate()).extractSecret(enc.getEncapsulation())));

        FalconKeyPairGenerator falconGen = new FalconKeyPairGenerator();
        falconGen.init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_1024));
        AsymmetricCipherKeyPair falconKp = falconGen.generateKeyPair();
        org.bouncycastle.pqc.crypto.falcon.FalconSigner falconSigner = new org.bouncycastle.pqc.crypto.falcon.FalconSigner();
        falconSigner.init(true, falconKp.getPrivate());
        sig = falconSigner.generateSignature(msg);
        falconSigner.init(false, falconKp.getPublic());
        isTrue("Falcon-1024", falconSigner.verifySignature(msg, sig));

        // and the weaker sets are still refused by the policy itself
        expectRefused(new MLDSAKeyPairGenerator(), new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65), 192);
        expectRefused(new MLKEMKeyPairGenerator(), new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768), 192);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testServiceNames()
    {
        final List<CryptoServiceProperties> seen = new ArrayList<CryptoServiceProperties>();

        CryptoServicesRegistrar.setServicesConstraints(new CryptoServicesConstraints()
        {
            public void check(CryptoServiceProperties service)
            {
                seen.add(service);
            }
        });

        MLKEMKeyPairGenerator mlkemGen = new MLKEMKeyPairGenerator();
        mlkemGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair mlkemKp = mlkemGen.generateKeyPair();
        new MLKEMGenerator(random).generateEncapsulated(mlkemKp.getPublic());
        new MLKEMExtractor((MLKEMPrivateKeyParameters)mlkemKp.getPrivate());

        CryptoServicesRegistrar.setServicesConstraints(null);

        isTrue("too few services seen: " + seen.size(), seen.size() >= 3);
        checkService(seen, "ML-KEMKeyGen", CryptoServicePurpose.KEYGEN, 192);
        checkService(seen, "ML-KEM", CryptoServicePurpose.ENCRYPTION, 192);
        checkService(seen, "ML-KEM", CryptoServicePurpose.DECRYPTION, 192);

        for (int i = 0; i != seen.size(); i++)
        {
            CryptoServiceProperties service = seen.get(i);
            if (service.getServiceName().startsWith("ML-KEM"))
            {
                isTrue("ML-KEM reported as quantum-vulnerable", !ConstraintUtils.isQuantumVulnerable(service));
            }
        }
    }

    private void checkService(List<CryptoServiceProperties> seen, String name, CryptoServicePurpose purpose, int bits)
    {
        for (int i = 0; i != seen.size(); i++)
        {
            CryptoServiceProperties service = seen.get(i);
            if (name.equals(service.getServiceName()) && purpose == service.getPurpose())
            {
                isEquals(name + " bits", bits, service.bitsOfSecurity());
                return;
            }
        }
        fail("service " + name + " for " + purpose + " not reported");
    }

    private void testQuantumVulnerableSignal()
    {
        isTrue(ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("RSA", 112, null, CryptoServicePurpose.ANY)));
        isTrue(ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("rsakeygen", 112, null, CryptoServicePurpose.KEYGEN)));
        isTrue(ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("ECDSA", 128, null, CryptoServicePurpose.SIGNING)));
        isTrue(ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("X25519", 128, null, CryptoServicePurpose.AGREEMENT)));
        // an unfamiliar name is still recognised from the key it carries
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 10));
        RSAKeyParameters rsaKey = (RSAKeyParameters)rsaGen.generateKeyPair().getPublic();
        isTrue(ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("SomethingElse", 80, rsaKey, CryptoServicePurpose.ENCRYPTION)));

        isTrue(!ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("AES", 128, null, CryptoServicePurpose.ANY)));
        isTrue(!ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("SHA-256", 128, null, CryptoServicePurpose.ANY)));
        isTrue(!ConstraintUtils.isQuantumVulnerable(new DefaultServiceProperties("ML-DSA", 192, MLDSAParameters.ml_dsa_65, CryptoServicePurpose.SIGNING)));
    }

    private void testQuantumVulnerableConstraint()
    {
        isTrue(QuantumVulnerableConstraint.NIST_DEPRECATED_AFTER.before(QuantumVulnerableConstraint.NIST_DISALLOWED_AFTER));
        isEquals(1924992000000L, QuantumVulnerableConstraint.NIST_DEPRECATED_AFTER.getTime());    // 2031-01-01T00:00:00Z
        isEquals(2082758400000L, QuantumVulnerableConstraint.NIST_DISALLOWED_AFTER.getTime());    // 2036-01-01T00:00:00Z

        try
        {
            new QuantumVulnerableConstraint(FAR_FUTURE, PAST);
            fail("reversed dates accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("disallowedAfter cannot precede deprecatedAfter", e.getMessage());
        }

        Ed25519KeyPairGenerator edGen = new Ed25519KeyPairGenerator();
        edGen.init(new Ed25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair edKp = edGen.generateKeyPair();

        MLDSAKeyPairGenerator mldsaGen = new MLDSAKeyPairGenerator();
        mldsaGen.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65));
        AsymmetricCipherKeyPair mldsaKp = mldsaGen.generateKeyPair();

        RSAKeyGenerationParameters rsaParams = new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 2048, 25);

        // not yet deprecated: nothing changes
        CryptoServicesRegistrar.setServicesConstraints(new QuantumVulnerableConstraint(FAR_FUTURE, FAR_FUTURE));
        new RSAKeyPairGenerator().init(rsaParams);
        new Ed25519Signer().init(true, edKp.getPrivate());

        // deprecated: still allowed
        CryptoServicesRegistrar.setServicesConstraints(new QuantumVulnerableConstraint(PAST, FAR_FUTURE));
        new RSAKeyPairGenerator().init(rsaParams);
        new Ed25519Signer().init(true, edKp.getPrivate());

        // disallowed: key generation and signing are refused, verification is legacy use, PQC is untouched
        CryptoServicesRegistrar.setServicesConstraints(new QuantumVulnerableConstraint(PAST, PAST));
        try
        {
            new RSAKeyPairGenerator().init(rsaParams);
            fail("RSA key generation not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isTrue(e.getMessage(), e.getMessage().startsWith("quantum-vulnerable service RSAKeyGen is disallowed for KEYGEN after "));
        }
        try
        {
            new Ed25519Signer().init(true, edKp.getPrivate());
            fail("Ed25519 signing not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isTrue(e.getMessage(), e.getMessage().startsWith("quantum-vulnerable service Ed25519 is disallowed for SIGNING after "));
        }
        new Ed25519Signer().init(false, edKp.getPublic());
        new MLDSASigner().init(true, mldsaKp.getPrivate());
        new MLDSASigner().init(false, mldsaKp.getPublic());
        mldsaGen.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_44));

        // the NIST timetable itself: nothing is disallowed yet
        CryptoServicesRegistrar.setServicesConstraints(new QuantumVulnerableConstraint());
        new RSAKeyPairGenerator().init(rsaParams);
        new Ed25519Signer().init(true, edKp.getPrivate());

        // exceptions are honoured
        CryptoServicesRegistrar.setServicesConstraints(new QuantumVulnerableConstraint(PAST, PAST, Collections.singleton("Ed25519")));
        new Ed25519Signer().init(true, edKp.getPrivate());
        try
        {
            new RSAKeyPairGenerator().init(rsaParams);
            fail("RSA key generation not refused with Ed25519 exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            // expected
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void expectRefused(org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator generator,
        org.bouncycastle.crypto.KeyGenerationParameters params, int bits)
    {
        try
        {
            generator.init(params);
            fail(generator.getClass().getSimpleName() + " not refused at " + bits + " bits");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isTrue(e.getMessage(), e.getMessage().endsWith(" bits of security only " + bits));
        }
    }

    public static void main(String[] args)
    {
        runTest(new PQCConstraintsTest());
    }
}
