package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Which keys the parameter-set specific ML-DSA and SLH-DSA Signature services accept.
 * <p>
 * FIPS 204 sec. 5 and FIPS 205 define one key generation algorithm per parameter set, and a key it
 * produces carries no commitment to the pure mode over the pre-hash one, so a <b>pure</b> key is
 * usable for a HashML-DSA / HashSLH-DSA signature. Refusing it broke the common case of verifying a
 * pre-hash signature with a key taken from an X.509 certificate, which carries the pure OID
 * (github #2397).
 * <p>
 * The rule asserted here, for both algorithms and in both directions:
 * <ul>
 * <li>a pure key is accepted by the pre-hash Signature of its own parameter set;</li>
 * <li>a pre-hash key is <b>refused</b> by the pure Signature - naming a pre-hash parameter set
 * narrows the key to that mode, so the tolerance is one way only;</li>
 * <li>a key of any other parameter set is refused either way;</li>
 * <li>the unbound "ML-DSA" / "SLH-DSA" / "HASH-SLH-DSA" services, which name no parameter set,
 * keep accepting any key of their algorithm.</li>
 * </ul>
 */
public class PreHashKeyInteropTest
    extends TestCase
{
    private static final byte[] MSG = "the quick brown fox".getBytes();

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testMLDSAPureKeyAcceptedByPreHashSignature()
        throws Exception
    {
        assertAccepted("ML-DSA-44", "ML-DSA-44-WITH-SHA512");
        assertAccepted("ML-DSA-65", "ML-DSA-65-WITH-SHA512");
        assertAccepted("ML-DSA-87", "ML-DSA-87-WITH-SHA512");
    }

    public void testMLDSAPreHashKeyRefusedByPureSignature()
        throws Exception
    {
        assertRefused("ML-DSA-44-WITH-SHA512", "ML-DSA-44");
        assertRefused("ML-DSA-65-WITH-SHA512", "ML-DSA-65");
        assertRefused("ML-DSA-87-WITH-SHA512", "ML-DSA-87");
    }

    public void testMLDSAOtherParameterSetsRefused()
        throws Exception
    {
        assertRefused("ML-DSA-44", "ML-DSA-65");
        assertRefused("ML-DSA-87", "ML-DSA-65");
        assertRefused("ML-DSA-44", "ML-DSA-65-WITH-SHA512");
        assertRefused("ML-DSA-87", "ML-DSA-65-WITH-SHA512");
        assertRefused("ML-DSA-44-WITH-SHA512", "ML-DSA-65-WITH-SHA512");
    }

    public void testMLDSAMatchingKeysStillAccepted()
        throws Exception
    {
        assertAccepted("ML-DSA-44", "ML-DSA-44");
        assertAccepted("ML-DSA-65", "ML-DSA-65");
        assertAccepted("ML-DSA-87", "ML-DSA-87");
        assertAccepted("ML-DSA-65-WITH-SHA512", "ML-DSA-65-WITH-SHA512");

        // the unbound services name no parameter set, so they take a key of any of them
        assertAccepted("ML-DSA-44", "ML-DSA");
        assertAccepted("ML-DSA-87", "ML-DSA");
        assertAccepted("ML-DSA-65", "HASH-ML-DSA");
        assertAccepted("ML-DSA-65-WITH-SHA512", "HASH-ML-DSA");
    }

    public void testMLDSAOidNamedSignatures()
        throws Exception
    {
        // a pure key against the matching pre-hash OID: the certificate case from github #2397
        assertAccepted("ML-DSA-65", oid(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512));
        assertAccepted("ML-DSA-65", oid(NISTObjectIdentifiers.id_ml_dsa_65));
        assertRefused("ML-DSA-44", oid(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512));
    }

    public void testSLHDSAPureKeyAcceptedByPreHashSignature()
        throws Exception
    {
        assertAccepted("SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F-WITH-SHA256");
        assertAccepted("SLH-DSA-SHAKE-128F", "SLH-DSA-SHAKE-128F-WITH-SHAKE128");
        assertAccepted("SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-192F-WITH-SHA512");
    }

    public void testSLHDSAPreHashKeyRefusedByPureSignature()
        throws Exception
    {
        assertRefused("SLH-DSA-SHA2-128F-WITH-SHA256", "SLH-DSA-SHA2-128F");
        assertRefused("SLH-DSA-SHAKE-128F-WITH-SHAKE128", "SLH-DSA-SHAKE-128F");
    }

    public void testSLHDSAOtherParameterSetsRefused()
        throws Exception
    {
        assertRefused("SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192F");
        assertRefused("SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F");
        assertRefused("SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128S");
        assertRefused("SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-128F-WITH-SHAKE128");
        assertRefused("SLH-DSA-SHA2-128F-WITH-SHA256", "SLH-DSA-SHA2-192F-WITH-SHA512");
    }

    public void testSLHDSAMatchingKeysStillAccepted()
        throws Exception
    {
        assertAccepted("SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F");
        assertAccepted("SLH-DSA-SHAKE-128F", "SLH-DSA-SHAKE-128F");
        assertAccepted("SLH-DSA-SHA2-128F-WITH-SHA256", "SLH-DSA-SHA2-128F-WITH-SHA256");

        // the unbound services name no parameter set, so they take a key of any of them
        assertAccepted("SLH-DSA-SHA2-128F", "SLH-DSA");
        assertAccepted("SLH-DSA-SHAKE-256S", "SLH-DSA");
        assertAccepted("SLH-DSA-SHA2-128F", "HASH-SLH-DSA");
        assertAccepted("SLH-DSA-SHA2-128F-WITH-SHA256", "HASH-SLH-DSA");
    }

    /**
     * The unbound "ML-DSA" and "SLH-DSA" services name no parameter set, so the SPI has nothing to
     * check a key against - but a pre-hash key is still refused there, by the lightweight signer,
     * which reports it as an IllegalArgumentException rather than an InvalidKeyException. Asserted
     * so that the one-way rule is known to hold on the unbound services too, by whatever route.
     */
    public void testPreHashKeyRefusedByUnboundPureSignature()
        throws Exception
    {
        assertRefusedByLightweightSigner("ML-DSA-65-WITH-SHA512", "ML-DSA", "\"pure\" ml-dsa must use non pre-hash parameters");
        assertRefusedByLightweightSigner("SLH-DSA-SHA2-128F-WITH-SHA256", "SLH-DSA", "\"pure\" slh-dsa must use non pre-hash parameters");
    }

    private void assertRefusedByLightweightSigner(String keyAlgorithm, String signatureAlgorithm, String message)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(keyAlgorithm, "BC").generateKeyPair();
        String where = keyAlgorithm + " key with " + signatureAlgorithm + " signature";

        try
        {
            Signature signer = Signature.getInstance(signatureAlgorithm, "BC");
            signer.initSign(kp.getPrivate());
            signer.update(MSG);
            signer.sign();
            fail(where + ": private key accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals(where, message, e.getMessage());
        }
    }

    public void testSLHDSAOidNamedSignatures()
        throws Exception
    {
        assertAccepted("SLH-DSA-SHA2-128F", oid(NISTObjectIdentifiers.id_slh_dsa_sha2_128f));
        assertAccepted("SLH-DSA-SHA2-128F", oid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256));
        assertRefused("SLH-DSA-SHA2-128F", oid(NISTObjectIdentifiers.id_slh_dsa_sha2_192s));
        assertRefused("SLH-DSA-SHA2-128F", oid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512));

        // the OID aliases are index-matched to their algorithm names in the registration, so a
        // mis-ordered array would show up as an OID resolving to the wrong parameter set
        assertAccepted("SLH-DSA-SHAKE-192S", oid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256));
        assertAccepted("SLH-DSA-SHAKE-256F", oid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256));
        assertAccepted("SLH-DSA-SHA2-256S", oid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512));
    }

    private static String oid(ASN1ObjectIdentifier oid)
    {
        return oid.getId();
    }

    private void assertAccepted(String keyAlgorithm, String signatureAlgorithm)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(keyAlgorithm, "BC").generateKeyPair();

        Signature signer = Signature.getInstance(signatureAlgorithm, "BC");

        signer.initSign(kp.getPrivate());
        signer.update(MSG);

        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(signatureAlgorithm, "BC");

        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);

        assertTrue(keyAlgorithm + " key with " + signatureAlgorithm + " signature", verifier.verify(sig));
    }

    private void assertRefused(String keyAlgorithm, String signatureAlgorithm)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(keyAlgorithm, "BC").generateKeyPair();
        String where = keyAlgorithm + " key with " + signatureAlgorithm + " signature";

        try
        {
            Signature signer = Signature.getInstance(signatureAlgorithm, "BC");
            signer.initSign(kp.getPrivate());
            fail(where + ": private key accepted");
        }
        catch (InvalidKeyException e)
        {
            assertTrue(where + ": " + e.getMessage(),
                e.getMessage().startsWith("signature configured for "));
        }

        try
        {
            Signature verifier = Signature.getInstance(signatureAlgorithm, "BC");
            verifier.initVerify(kp.getPublic());
            fail(where + ": public key accepted");
        }
        catch (InvalidKeyException e)
        {
            assertTrue(where + ": " + e.getMessage(),
                e.getMessage().startsWith("signature configured for "));
        }
    }
}
