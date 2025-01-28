package org.bouncycastle.openpgp.test;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;

import java.util.Date;

public class PGPKeyPairGeneratorTest
    extends AbstractPgpKeyPairTest
{

    @Override
    public String getName()
    {
        return "PGPKeyPairGeneratorTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        performWith(new Factory()
        {
            @Override
            public PGPKeyPairGenerator create(int version, Date creationTime)
            {
                return new BcPGPKeyPairGeneratorProvider()
                    .get(version, creationTime);
            }
        });
        performWith(new Factory()
        {
            @Override
            public PGPKeyPairGenerator create(int version, Date creationTime)
            {
                return new JcaPGPKeyPairGeneratorProvider()
                    .setProvider(new BouncyCastleProvider())
                    .get(version, creationTime);
            }
        });
    }

    private void performWith(Factory factory)
        throws PGPException
    {
        testGenerateV4RsaKey(factory);
        testGenerateV6RsaKey(factory);

        testGenerateV6Ed448Key(factory);
        testGenerateV4Ed448Key(factory);

        testGenerateV6Ed25519Key(factory);
        testGenerateV4Ed25519Key(factory);

        testGenerateV6X448Key(factory);
        testGenerateV4X448Key(factory);

        testGenerateV6X25519Key(factory);
        testGenerateV4X25519Key(factory);

        // Legacy formats
        testGenerateV6LegacyEd25519KeyFails(factory);
        testGenerateV4LegacyEd215519Key(factory);

        testGenerateV6LegacyX25519KeyFails(factory);
        testGenerateV4LegacyX215519Key(factory);

        // NIST
        testGenerateV4P256ECDHKey(factory);
        testGenerateV6P256ECDHKey(factory);

        testGenerateV4P384ECDHKey(factory);
        testGenerateV6P384ECDHKey(factory);

        testGenerateV4P521ECDHKey(factory);
        testGenerateV6P521ECDHKey(factory);

        testGenerateV4P256ECDSAKey(factory);
        testGenerateV6P256ECDSAKey(factory);

        testGenerateV4P384ECDSAKey(factory);
        testGenerateV6P384ECDSAKey(factory);

        testGenerateV4P521ECDSAKey(factory);
        testGenerateV6P521ECDSAKey(factory);
    }

    private void testGenerateV4RsaKey(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);
        PGPKeyPair kp = gen.generateRsaKeyPair(3072);

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.RSA_GENERAL);
        isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getBitStrength(), 3072);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6RsaKey(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);
        PGPKeyPair kp = gen.generateRsaKeyPair(4096);

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.RSA_GENERAL);
        isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getBitStrength(), 4096);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6Ed25519Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);
        PGPKeyPair kp = gen.generateEd25519KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.Ed25519);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), Ed25519PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4Ed25519Key(Factory factory)
        throws PGPException
    {

        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);
        PGPKeyPair kp = gen.generateEd25519KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.Ed25519);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), Ed25519PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6Ed448Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);
        PGPKeyPair kp = gen.generateEd448KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.Ed448);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), Ed448PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4Ed448Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);
        PGPKeyPair kp = gen.generateEd448KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.Ed448);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), Ed448PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6X25519Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);
        PGPKeyPair kp = gen.generateX25519KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.X25519);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), X25519PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4X25519Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);
        PGPKeyPair kp = gen.generateX25519KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.X25519);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), X25519PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6X448Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);
        PGPKeyPair kp = gen.generateX448KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.X448);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), X448PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4X448Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);
        PGPKeyPair kp = gen.generateX448KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.X448);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), X448PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }


    private void testGenerateV4LegacyEd215519Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);
        PGPKeyPair kp = gen.generateLegacyEd25519KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.EDDSA_LEGACY);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), Ed25519PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6LegacyEd25519KeyFails(Factory factory)
    {
        Date creationTime = currentTimeRounded();
        final PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);
        isNotNull(
            "Expected exception when attempting to generate v6 LegacyEd25519 key with (" + gen.getClass().getName() + ")",
            testException(
                "An implementation MUST NOT generate a v6 LegacyEd25519 key pair.",
                "PGPException",
                new TestExceptionOperation()
                {
                    @Override
                    public void operation()
                        throws Exception
                    {
                        gen.generateLegacyEd25519KeyPair();
                    }
                }));
    }

    private void testGenerateV6LegacyX25519KeyFails(Factory factory)
    {
        Date creationTime = currentTimeRounded();
        final PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);
        isNotNull(
            "Expected exception when attempting to generate v6 LegacyX25519 key with (" + gen.getClass().getName() + ")",
            testException(
                "An implementation MUST NOT generate a v6 LegacyX25519 key pair.",
                "PGPException",
                new TestExceptionOperation()
                {
                    @Override
                    public void operation()
                        throws Exception
                    {
                        gen.generateLegacyX25519KeyPair();
                    }
                }));
    }

    private void testGenerateV4LegacyX215519Key(Factory factory)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);
        PGPKeyPair kp = gen.generateLegacyX25519KeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDH);
        // isEquals("Key bit-strength mismatch (" + gen.getClass().getName() + ")",
        //         kp.getPublicKey().getBitStrength(), X25519PublicBCPGKey.LENGTH * 8);
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
            kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4P256ECDHKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);

        PGPKeyPair kp = gen.generateNistP256ECDHKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDH);
        ECDHPublicBCPGKey k = (ECDHPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp256r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4P384ECDHKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);

        PGPKeyPair kp = gen.generateNistP384ECDHKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDH);
        ECDHPublicBCPGKey k = (ECDHPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp384r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4P521ECDHKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);

        PGPKeyPair kp = gen.generateNistP521ECDHKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDH);
        ECDHPublicBCPGKey k = (ECDHPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp521r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4P256ECDSAKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);

        PGPKeyPair kp = gen.generateNistP256ECDSAKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDSA);
        ECDSAPublicBCPGKey k = (ECDSAPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp256r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4P384ECDSAKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);

        PGPKeyPair kp = gen.generateNistP384ECDSAKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDSA);
        ECDSAPublicBCPGKey k = (ECDSAPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp384r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV4P521ECDSAKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_4, creationTime);

        PGPKeyPair kp = gen.generateNistP521ECDSAKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_4);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDSA);
        ECDSAPublicBCPGKey k = (ECDSAPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp521r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6P256ECDHKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);

        PGPKeyPair kp = gen.generateNistP256ECDHKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDH);
        ECDHPublicBCPGKey k = (ECDHPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp256r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6P384ECDHKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);

        PGPKeyPair kp = gen.generateNistP384ECDHKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDH);
        ECDHPublicBCPGKey k = (ECDHPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp384r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6P521ECDHKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);

        PGPKeyPair kp = gen.generateNistP521ECDHKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDH);
        ECDHPublicBCPGKey k = (ECDHPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp521r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6P256ECDSAKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);

        PGPKeyPair kp = gen.generateNistP256ECDSAKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDSA);
        ECDSAPublicBCPGKey k = (ECDSAPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp256r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6P384ECDSAKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);

        PGPKeyPair kp = gen.generateNistP384ECDSAKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDSA);
        ECDSAPublicBCPGKey k = (ECDSAPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp384r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    private void testGenerateV6P521ECDSAKey(Factory factory)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        PGPKeyPairGenerator gen = factory.create(PublicKeyPacket.VERSION_6, creationTime);

        PGPKeyPair kp = gen.generateNistP521ECDSAKeyPair();

        isEquals("Key version mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getVersion(), PublicKeyPacket.VERSION_6);
        isEquals("Key algorithm mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getAlgorithm(), PublicKeyAlgorithmTags.ECDSA);
        ECDSAPublicBCPGKey k = (ECDSAPublicBCPGKey) kp.getPublicKey().getPublicKeyPacket().getKey();
        isEquals(SECObjectIdentifiers.secp521r1, k.getCurveOID());
        isEquals("Key creation time mismatch (" + gen.getClass().getName() + ")",
                kp.getPublicKey().getCreationTime(), creationTime);
    }

    public static void main(String[] args)
    {
        runTest(new PGPKeyPairGeneratorTest());
    }

    @FunctionalInterface
    private interface Factory
    {
        PGPKeyPairGenerator create(int version, Date creationTime);
    }
}
