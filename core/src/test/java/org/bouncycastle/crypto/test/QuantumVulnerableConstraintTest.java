package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.constraints.LoggingConstraint;
import org.bouncycastle.crypto.constraints.QuantumVulnerableConstraint;
import org.bouncycastle.crypto.constraints.ServicesConstraint;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.kems.ECIESKeyEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The three fixed QuantumVulnerableConstraint policies - log only, legacy use only and reject all -
 * against every purpose, through the light-weight RSA, EC, X25519, ECIES, ML-KEM and ML-DSA
 * classes, together with the policy names the default-constraint property accepts and a
 * LoggingConstraint recording the post-quantum services.
 */
public class QuantumVulnerableConstraintTest
    extends SimpleTest
{
    private static final Logger LOG = Logger.getLogger(ServicesConstraint.class.getName());

    private final SecureRandom random = new SecureRandom();

    public String getName()
    {
        return "QuantumVulnerableConstraint";
    }

    public void performTest()
        throws Exception
    {
        try
        {
            testPurposeMatrix();
            testSigning();
            testEncryptionAndAgreement();
            testPostQuantumUnaffected();
            testLogOnlyLogs();
            testLoggingConstraint();
            testPolicyNames();
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
        }
    }

    /*
     * every purpose against every policy, straight through check()
     */
    private void testPurposeMatrix()
    {
        CryptoServicePurpose[] purposes = CryptoServicePurpose.values();

        for (int i = 0; i != purposes.length; i++)
        {
            CryptoServicePurpose purpose = purposes[i];
            DefaultServiceProperties rsa = new DefaultServiceProperties("RSA", 128, null, purpose);
            DefaultServiceProperties aes = new DefaultServiceProperties("AES", 128, null, purpose);

            boolean legacy = purpose == CryptoServicePurpose.VERIFYING || purpose == CryptoServicePurpose.VERIFICATION
                || purpose == CryptoServicePurpose.DECRYPTION || purpose == CryptoServicePurpose.ANY;

            withLogSilenced();
            try
            {
                QuantumVulnerableConstraint.logOnly().check(rsa);

                checkMatrix(QuantumVulnerableConstraint.legacyUseOnly(), rsa, legacy);
                checkMatrix(QuantumVulnerableConstraint.rejectAll(), rsa, false);

                // the exceptions set is honoured in every mode
                QuantumVulnerableConstraint.rejectAll(Collections.singleton("RSA")).check(rsa);
                QuantumVulnerableConstraint.legacyUseOnly(Collections.singleton("rsa")).check(rsa);

                // nothing but the quantum-vulnerable algorithms is affected
                QuantumVulnerableConstraint.rejectAll().check(aes);
            }
            finally
            {
                restoreLog();
            }
        }
    }

    private void checkMatrix(QuantumVulnerableConstraint constraint, DefaultServiceProperties service, boolean allowed)
    {
        try
        {
            constraint.check(service);
            isTrue("RSA for " + service.getPurpose() + " not refused", allowed);
        }
        catch (CryptoServiceConstraintsException e)
        {
            isTrue("RSA for " + service.getPurpose() + " refused: " + e.getMessage(), !allowed);
            isEquals("quantum-vulnerable service RSA is disallowed for " + service.getPurpose(), e.getMessage());
        }
    }

    /*
     * the acceptance case: RSA and ECDSA signing refused, verification allowed - and refused too under rejectAll()
     */
    private void testSigning()
    {
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 25));
        final AsymmetricCipherKeyPair rsaKp = rsaGen.generateKeyPair();

        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
        ecGen.init(new ECKeyGenerationParameters(new ECDomainParameters(ECNamedCurveTable.getByName("P-256")), random));
        final AsymmetricCipherKeyPair ecKp = ecGen.generateKeyPair();

        withLogSilenced();
        try
        {
            CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.legacyUseOnly());

            expectRefused("RSA", CryptoServicePurpose.SIGNING, new Runnable()
            {
                public void run()
                {
                    new RSADigestSigner(new SHA256Digest()).init(true, rsaKp.getPrivate());
                }
            });
            expectRefused("RSA", CryptoServicePurpose.SIGNING, new Runnable()
            {
                public void run()
                {
                    new PSSSigner(new RSAEngine(), new SHA256Digest(), 32).init(true, new ParametersWithRandom(rsaKp.getPrivate(), random));
                }
            });
            expectRefused("ECDSA", CryptoServicePurpose.SIGNING, new Runnable()
            {
                public void run()
                {
                    new ECDSASigner().init(true, new ParametersWithRandom(ecKp.getPrivate(), random));
                }
            });
            expectRefused("RSAKeyGen", CryptoServicePurpose.KEYGEN, new Runnable()
            {
                public void run()
                {
                    new RSAKeyPairGenerator().init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 25));
                }
            });
            expectRefused("ECKeyGen", CryptoServicePurpose.KEYGEN, new Runnable()
            {
                public void run()
                {
                    new ECKeyPairGenerator().init(new ECKeyGenerationParameters(new ECDomainParameters(ECNamedCurveTable.getByName("P-256")), random));
                }
            });

            new RSADigestSigner(new SHA256Digest()).init(false, rsaKp.getPublic());
            new PSSSigner(new RSAEngine(), new SHA256Digest(), 32).init(false, rsaKp.getPublic());
            new ECDSASigner().init(false, ecKp.getPublic());

            CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.rejectAll());

            expectRefused("RSA", CryptoServicePurpose.VERIFYING, new Runnable()
            {
                public void run()
                {
                    new RSADigestSigner(new SHA256Digest()).init(false, rsaKp.getPublic());
                }
            });
            expectRefused("ECDSA", CryptoServicePurpose.VERIFYING, new Runnable()
            {
                public void run()
                {
                    new ECDSASigner().init(false, ecKp.getPublic());
                }
            });

            CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.logOnly());

            new RSADigestSigner(new SHA256Digest()).init(true, rsaKp.getPrivate());
            new ECDSASigner().init(true, new ParametersWithRandom(ecKp.getPrivate(), random));
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
            restoreLog();
        }
    }

    private void testEncryptionAndAgreement()
        throws Exception
    {
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 25));
        final AsymmetricCipherKeyPair rsaKp = rsaGen.generateKeyPair();

        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
        ecGen.init(new ECKeyGenerationParameters(new ECDomainParameters(ECNamedCurveTable.getByName("P-256")), random));
        final AsymmetricCipherKeyPair ecKp = ecGen.generateKeyPair();

        X25519KeyPairGenerator xGen = new X25519KeyPairGenerator();
        xGen.init(new X25519KeyGenerationParameters(random));
        final AsymmetricCipherKeyPair xKp = xGen.generateKeyPair();

        withLogSilenced();
        try
        {
            CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.legacyUseOnly());

            expectRefused("RSA", CryptoServicePurpose.ENCRYPTION, new Runnable()
            {
                public void run()
                {
                    new OAEPEncoding(new RSAEngine()).init(true, new ParametersWithRandom(rsaKp.getPublic(), random));
                }
            });
            new OAEPEncoding(new RSAEngine()).init(false, rsaKp.getPrivate());

            // key agreement is new protection, not legacy use
            expectRefused("ECDH", CryptoServicePurpose.AGREEMENT, new Runnable()
            {
                public void run()
                {
                    new ECDHBasicAgreement().init(ecKp.getPrivate());
                }
            });
            expectRefused("X25519", CryptoServicePurpose.AGREEMENT, new Runnable()
            {
                public void run()
                {
                    new X25519Agreement().init(xKp.getPrivate());
                }
            });

            // ECIESKeyEncapsulation reports ANY for both directions, which only legacy use can admit
            new ECIESKeyEncapsulation(new KDF2BytesGenerator(new SHA256Digest()), random).init(ecKp.getPublic());

            CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.rejectAll());

            expectRefused("RSA", CryptoServicePurpose.DECRYPTION, new Runnable()
            {
                public void run()
                {
                    new OAEPEncoding(new RSAEngine()).init(false, rsaKp.getPrivate());
                }
            });
            expectRefused("ECIESKem", CryptoServicePurpose.ANY, new Runnable()
            {
                public void run()
                {
                    new ECIESKeyEncapsulation(new KDF2BytesGenerator(new SHA256Digest()), random).init(ecKp.getPrivate());
                }
            });
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
            restoreLog();
        }
    }

    private void testPostQuantumUnaffected()
        throws Exception
    {
        CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.rejectAll());
        try
        {
            MLKEMKeyPairGenerator kemGen = new MLKEMKeyPairGenerator();
            kemGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
            AsymmetricCipherKeyPair kemKp = kemGen.generateKeyPair();
            SecretWithEncapsulation secret = new MLKEMGenerator(random).generateEncapsulated(kemKp.getPublic());
            byte[] extracted = new MLKEMExtractor((MLKEMPrivateKeyParameters)kemKp.getPrivate()).extractSecret(secret.getEncapsulation());
            isTrue(areEqual(secret.getSecret(), extracted));

            MLDSAKeyPairGenerator dsaGen = new MLDSAKeyPairGenerator();
            dsaGen.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65));
            AsymmetricCipherKeyPair dsaKp = dsaGen.generateKeyPair();
            byte[] msg = new byte[32];

            MLDSASigner signer = new MLDSASigner();
            signer.init(true, dsaKp.getPrivate());
            signer.update(msg, 0, msg.length);
            byte[] sig = signer.generateSignature();

            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, dsaKp.getPublic());
            verifier.update(msg, 0, msg.length);
            isTrue(verifier.verifySignature(sig));
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
        }
    }

    private void testLogOnlyLogs()
    {
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 25));
        AsymmetricCipherKeyPair rsaKp = rsaGen.generateKeyPair();

        List<String> messages = new ArrayList<String>();
        Handler handler = capture(messages);
        try
        {
            CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.logOnly());
            new RSADigestSigner(new SHA256Digest()).init(true, rsaKp.getPrivate());

            CryptoServicesRegistrar.setServicesConstraints(QuantumVulnerableConstraint.logOnly(Collections.singleton("RSA")));
            new RSADigestSigner(new SHA256Digest()).init(false, rsaKp.getPublic());
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
            release(handler);
        }

        isTrue("signing not logged: " + messages, contains(messages, "quantum-vulnerable service RSA for SIGNING"));
        isTrue("exception logged: " + messages, !contains(messages, "RSA for VERIFYING"));
    }

    /*
     * the acceptance case: a LoggingConstraint records ML-KEM and ML-DSA use
     */
    private void testLoggingConstraint()
    {
        List<String> messages = new ArrayList<String>();
        Handler handler = capture(messages);
        try
        {
            CryptoServicesRegistrar.setServicesConstraints(new LoggingConstraint());

            MLKEMKeyPairGenerator kemGen = new MLKEMKeyPairGenerator();
            kemGen.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
            AsymmetricCipherKeyPair kemKp = kemGen.generateKeyPair();
            SecretWithEncapsulation secret = new MLKEMGenerator(random).generateEncapsulated(kemKp.getPublic());
            new MLKEMExtractor((MLKEMPrivateKeyParameters)kemKp.getPrivate()).extractSecret(secret.getEncapsulation());

            MLDSAKeyPairGenerator dsaGen = new MLDSAKeyPairGenerator();
            dsaGen.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_44));
            AsymmetricCipherKeyPair dsaKp = dsaGen.generateKeyPair();
            new MLDSASigner().init(true, dsaKp.getPrivate());
            new MLDSASigner().init(false, dsaKp.getPublic());

            CryptoServicesRegistrar.setServicesConstraints(new LoggingConstraint(Collections.singleton("ML-DSA")));
            new MLDSASigner().init(false, dsaKp.getPublic());
        }
        finally
        {
            CryptoServicesRegistrar.setServicesConstraints(null);
            release(handler);
        }

        isTrue(messages.toString(), contains(messages, "[ML-KEMKeyGen, 192, KEYGEN]"));
        isTrue(messages.toString(), contains(messages, "[ML-KEM, 192, ENCRYPTION]"));
        isTrue(messages.toString(), contains(messages, "[ML-KEM, 192, DECRYPTION]"));
        isTrue(messages.toString(), contains(messages, "[ML-DSAKeyGen, 128, KEYGEN]"));
        isTrue(messages.toString(), contains(messages, "[ML-DSA, 128, SIGNING]"));
        isEquals(messages.toString(), 1, count(messages, "[ML-DSA, 128, VERIFYING]"));
    }

    private void testPolicyNames()
    {
        isTrue(QuantumVulnerableConstraint.forPolicy("none") == null);
        isTrue(QuantumVulnerableConstraint.forPolicy(" None ") == null);
        isTrue(QuantumVulnerableConstraint.forPolicy("nist") != null);
        isTrue(QuantumVulnerableConstraint.forPolicy("LOG") != null);
        isTrue(QuantumVulnerableConstraint.forPolicy("legacy") != null);
        isTrue(QuantumVulnerableConstraint.forPolicy("Reject") != null);

        DefaultServiceProperties rsaSign = new DefaultServiceProperties("RSA", 128, null, CryptoServicePurpose.SIGNING);
        DefaultServiceProperties rsaVerify = new DefaultServiceProperties("RSA", 128, null, CryptoServicePurpose.VERIFYING);

        withLogSilenced();
        try
        {
            // the NIST dates are in the future, so the timetable refuses nothing yet
            QuantumVulnerableConstraint.forPolicy("nist").check(rsaSign);
            QuantumVulnerableConstraint.forPolicy("log").check(rsaSign);
            QuantumVulnerableConstraint.forPolicy("legacy").check(rsaVerify);
            checkMatrix(QuantumVulnerableConstraint.forPolicy("legacy"), rsaSign, false);
            checkMatrix(QuantumVulnerableConstraint.forPolicy("reject"), rsaVerify, false);
        }
        finally
        {
            restoreLog();
        }

        try
        {
            QuantumVulnerableConstraint.forPolicy("strict");
            fail("unknown policy accepted");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("unknown quantum-vulnerable policy: strict", e.getMessage());
        }
    }

    private void expectRefused(String service, CryptoServicePurpose purpose, Runnable operation)
    {
        try
        {
            operation.run();
            fail(service + " for " + purpose + " not refused");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("quantum-vulnerable service " + service + " is disallowed for " + purpose, e.getMessage());
        }
    }

    private static boolean contains(List<String> messages, String fragment)
    {
        return count(messages, fragment) != 0;
    }

    private static int count(List<String> messages, String fragment)
    {
        int count = 0;
        for (int i = 0; i != messages.size(); i++)
        {
            if (((String)messages.get(i)).indexOf(fragment) >= 0)
            {
                count++;
            }
        }
        return count;
    }

    private Level savedLevel;
    private boolean savedUseParentHandlers;

    private void withLogSilenced()
    {
        savedLevel = LOG.getLevel();
        savedUseParentHandlers = LOG.getUseParentHandlers();
        LOG.setUseParentHandlers(false);
    }

    private void restoreLog()
    {
        LOG.setLevel(savedLevel);
        LOG.setUseParentHandlers(savedUseParentHandlers);
    }

    private Handler capture(final List<String> messages)
    {
        withLogSilenced();
        LOG.setLevel(Level.INFO);

        Handler handler = new Handler()
        {
            public void publish(LogRecord record)
            {
                messages.add(record.getMessage());
            }

            public void flush()
            {
            }

            public void close()
            {
            }
        };
        LOG.addHandler(handler);

        return handler;
    }

    private void release(Handler handler)
    {
        LOG.removeHandler(handler);
        restoreLog();
    }

    public static void main(String[] args)
    {
        runTest(new QuantumVulnerableConstraintTest());
    }
}
