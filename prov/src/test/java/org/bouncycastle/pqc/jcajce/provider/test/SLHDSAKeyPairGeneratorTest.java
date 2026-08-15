package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.SLHDSAKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;


/**
 * KeyFactory/KeyPairGenerator tests for SLHDSA with the BC provider.
 */
public class SLHDSAKeyPairGeneratorTest
    extends MainProvKeyPairGeneratorTest
{

    protected void setUp()
    {
        super.setUp();
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testKeyFactory()
        throws Exception
    {
        kf = KeyFactory.getInstance("SLH-DSA", "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_sha2_128s.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_sha2_128f.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_sha2_192s.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_sha2_192f.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_sha2_256s.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_sha2_256f.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_shake_128s.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_shake_128f.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_shake_192s.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_shake_192f.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_shake_256s.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_slh_dsa_shake_256f.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256.getId(), "BC");
        kf = KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256.getId(), "BC");
    }

    public void testKeySpecs()
        throws Exception
    {
        kf = KeyFactory.getInstance("SLH-DSA", "BC");
        kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        KeyPair kp = kpg.generateKeyPair();

        PKCS8EncodedKeySpec privSpec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);

        assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), privSpec.getEncoded()));

        X509EncodedKeySpec pubSpec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);

        assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pubSpec.getEncoded()));
    }

    public void testKeyPairEncoding()
        throws Exception
    {
        kf = KeyFactory.getInstance("HASH-SLH-DSA", "BC");

        SLHDSAParameterSpec[] params =
            {
                SLHDSAParameterSpec.slh_dsa_sha2_128s,
                SLHDSAParameterSpec.slh_dsa_sha2_128f,
                SLHDSAParameterSpec.slh_dsa_sha2_192s,
                SLHDSAParameterSpec.slh_dsa_sha2_192f,
                SLHDSAParameterSpec.slh_dsa_sha2_256s,
                SLHDSAParameterSpec.slh_dsa_sha2_256f,

                SLHDSAParameterSpec.slh_dsa_shake_128s,
                SLHDSAParameterSpec.slh_dsa_shake_128f,
                SLHDSAParameterSpec.slh_dsa_shake_192s,
                SLHDSAParameterSpec.slh_dsa_shake_192f,
                SLHDSAParameterSpec.slh_dsa_shake_256s,
                SLHDSAParameterSpec.slh_dsa_shake_256f,

                SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256,
                SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256,
                SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512,
                SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512,
                SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512,
                SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512,

                SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128,
                SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128,
                SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256,
                SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256,
                SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256,
                SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256,
            };

        // expected object identifiers
        ASN1ObjectIdentifier[] oids =
            {
                NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
                NISTObjectIdentifiers.id_slh_dsa_shake_128s,
                NISTObjectIdentifiers.id_slh_dsa_shake_128f,
                NISTObjectIdentifiers.id_slh_dsa_shake_192s,
                NISTObjectIdentifiers.id_slh_dsa_shake_192f,
                NISTObjectIdentifiers.id_slh_dsa_shake_256s,
                NISTObjectIdentifiers.id_slh_dsa_shake_256f,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256
            };

        kpg = KeyPairGenerator.getInstance("HASH-SLH-DSA", "BC");

        for (int i = 0; i != params.length; i++)
        {
            kpg.initialize(params[i], new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            performKeyPairEncodingTest(keyPair);
            performKeyPairEncodingTest(params[i].getName(), keyPair);
            performKeyPairEncodingTest(oids[i].getId(), keyPair);
            assertNotNull(((SLHDSAPrivateKey)keyPair.getPrivate()).getParameterSpec());
            assertNotNull(((SLHDSAPublicKey)keyPair.getPublic()).getParameterSpec());
            assertEquals(oids[i], SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()).getAlgorithm().getAlgorithm());
            assertTrue(oids[i].toString(), Arrays.areEqual(((SLHDSAPublicKey)keyPair.getPublic()).getPublicData(), ((SLHDSAPrivateKey)keyPair.getPrivate()).getPublicKey().getPublicData()));
        }

        //
        // a bit of a cheat as we just look for "getName()" on the parameter spec.
        //
        for (int i = 0; i != params.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(params[i].getName(), "BC");
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toLowerCase(params[i].getName())));
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toUpperCase(params[i].getName())));
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toLowerCase(params[i].getName())), new SecureRandom());
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toUpperCase(params[i].getName())), new SecureRandom());
        }

        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(params[0].getName(), "BC");
            kpg.initialize(new ECNamedCurveGenParameterSpec(Strings.toLowerCase("Not Valid")));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("unknown parameter set name: NOT VALID", e.getMessage());
        }
    }

    public void testCrossNaming()
        throws Exception
    {
        ASN1ObjectIdentifier[] nistOids = new ASN1ObjectIdentifier[]
            {
                NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
                NISTObjectIdentifiers.id_slh_dsa_shake_128s,
                NISTObjectIdentifiers.id_slh_dsa_shake_128f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
                NISTObjectIdentifiers.id_slh_dsa_shake_192s,
                NISTObjectIdentifiers.id_slh_dsa_shake_192f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
                NISTObjectIdentifiers.id_slh_dsa_shake_256s,
                NISTObjectIdentifiers.id_slh_dsa_shake_256f,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256,
                NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256
            };

        SLHDSAParameterSpec[] specs = new SLHDSAParameterSpec[]
            {
                SLHDSAParameterSpec.slh_dsa_sha2_128s,
                SLHDSAParameterSpec.slh_dsa_sha2_128f,
                SLHDSAParameterSpec.slh_dsa_shake_128s,
                SLHDSAParameterSpec.slh_dsa_shake_128f,
                SLHDSAParameterSpec.slh_dsa_sha2_192s,
                SLHDSAParameterSpec.slh_dsa_sha2_192f,
                SLHDSAParameterSpec.slh_dsa_shake_192s,
                SLHDSAParameterSpec.slh_dsa_shake_192f,
                SLHDSAParameterSpec.slh_dsa_sha2_256s,
                SLHDSAParameterSpec.slh_dsa_sha2_256f,
                SLHDSAParameterSpec.slh_dsa_shake_256s,
                SLHDSAParameterSpec.slh_dsa_shake_256f,
                SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256,
                SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256,
                SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128,
                SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128,
                SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512,
                SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512,
                SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256,
                SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256,
                SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512,
                SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512,
                SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256,
                SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256
            };

        for (int i = 0; i != nistOids.length; i++)
        {
            KeyPairGenerator ml_dsa_kp = KeyPairGenerator.getInstance(nistOids[i].getId(), "BC");
            KeyPair kp = ml_dsa_kp.generateKeyPair();

            assertEquals(specs[i].getName(), ((SLHDSAKey)kp.getPublic()).getParameterSpec().getName());
            assertEquals(specs[i].getName(), ((SLHDSAKey)kp.getPrivate()).getParameterSpec().getName());

            Signature ml_dsa_sig = deriveSignatureFromKey(kp.getPrivate());
        }
    }

    /**
     * A generator selected by parameter set name must default to that parameter set, not to the
     * generic generator's default of SLH-DSA-SHA2-128F, and must refuse to be re-pointed at a
     * different one - as the ML-DSA and ML-KEM generators alongside it do.
     */
    public void testNamedKeyPairGenDefaults()
        throws Exception
    {
        SLHDSAParameterSpec[] specs = new SLHDSAParameterSpec[]
            {
                SLHDSAParameterSpec.slh_dsa_sha2_128f,
                SLHDSAParameterSpec.slh_dsa_sha2_192f,
                SLHDSAParameterSpec.slh_dsa_sha2_256f,
                SLHDSAParameterSpec.slh_dsa_shake_128f,
                SLHDSAParameterSpec.slh_dsa_shake_192f,
                SLHDSAParameterSpec.slh_dsa_shake_256f,
                SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256,
                SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256
            };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(specs[i].getName(), "BC");

            assertEquals(specs[i].getName(), kpg.getAlgorithm());

            KeyPair kp = kpg.generateKeyPair();

            assertEquals(specs[i].getName(), ((SLHDSAKey)kp.getPublic()).getParameterSpec().getName());
            assertEquals(specs[i].getName(), ((SLHDSAKey)kp.getPrivate()).getParameterSpec().getName());
        }
    }

    public void testNamedKeyPairGenLocked()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(SLHDSAParameterSpec.slh_dsa_shake_256f.getName(), "BC");

        try
        {
            kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key pair generator locked to " + kpg.getAlgorithm(), e.getMessage());
        }

        kpg.initialize(SLHDSAParameterSpec.slh_dsa_shake_256f, new SecureRandom());

        assertEquals(SLHDSAParameterSpec.slh_dsa_shake_256f.getName(),
            ((SLHDSAKey)kpg.generateKeyPair().getPublic()).getParameterSpec().getName());
    }
    
    private static Signature deriveSignatureFromKey(Key key)
        throws Exception
    {
        return Signature.getInstance(key.getAlgorithm(), "BC");
    }
}
