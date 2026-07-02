package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

/**
 * Regression test for the Dilithium public/private key-factory wiring.
 * <p>
 * The round-3 era "AES" Dilithium variants (<code>dilithium2_aes</code> /
 * <code>dilithium3_aes</code> / <code>dilithium5_aes</code>) were dropped in the
 * ML-DSA (FIPS 204) migration - there is no lightweight <code>DilithiumParameters</code>
 * AES set. Historically <code>PublicKeyFactory</code> (and the
 * <code>BouncyCastleProvider.loadPQCKeys()</code> bridge) still registered converters
 * for those OIDs while <code>PrivateKeyFactory</code> / <code>Utils</code> did not, so a
 * <code>dilithium*_aes</code> public key decoded to a key carrying null parameters while
 * the matching private key threw "algorithm identifier in private key not recognised".
 * <p>
 * These tests pin the corrected behaviour: the supported dilithium2/3/5 OIDs round-trip
 * through both layers, and the vestigial <code>_aes</code> OIDs are now consistently
 * unsupported on the public and private sides (both lightweight factories reject, and the
 * BC provider bridge returns null).
 */
public class DilithiumFactoryConsistencyTest
    extends TestCase
{
    private static final DilithiumParameterSpec[] SUPPORTED_SPECS =
    {
        DilithiumParameterSpec.dilithium2,
        DilithiumParameterSpec.dilithium3,
        DilithiumParameterSpec.dilithium5
    };

    private static final ASN1ObjectIdentifier[] VESTIGIAL_AES_OIDS =
    {
        BCObjectIdentifiers.dilithium2_aes,
        BCObjectIdentifiers.dilithium3_aes,
        BCObjectIdentifiers.dilithium5_aes
    };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        // getPublicKey/getPrivateKey route through the static converter table that
        // loadPQCKeys() populates when a BouncyCastleProvider is constructed.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testSupportedDilithiumRoundTripsThroughFactories()
        throws Exception
    {
        for (int i = 0; i != SUPPORTED_SPECS.length; i++)
        {
            DilithiumParameterSpec spec = SUPPORTED_SPECS[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

            kpg.initialize(spec, new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

            // core lightweight factories
            AsymmetricKeyParameter pubParams = PublicKeyFactory.createKey(spki);
            AsymmetricKeyParameter privParams = PrivateKeyFactory.createKey(pki);

            assertTrue(spec.getName(), pubParams instanceof DilithiumPublicKeyParameters);
            assertTrue(spec.getName(), privParams instanceof DilithiumPrivateKeyParameters);

            // BouncyCastleProvider (BC) bridge populated by loadPQCKeys()
            assertNotNull(spec.getName(), BouncyCastleProvider.getPublicKey(spki));
            assertNotNull(spec.getName(), BouncyCastleProvider.getPrivateKey(pki));
        }
    }

    public void testVestigialAesVariantsConsistentlyUnsupported()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        kpg.initialize(DilithiumParameterSpec.dilithium2, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo dilithiumSpki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        PrivateKeyInfo dilithiumPki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        for (int i = 0; i != VESTIGIAL_AES_OIDS.length; i++)
        {
            ASN1ObjectIdentifier aesOid = VESTIGIAL_AES_OIDS[i];

            // re-tag a real Dilithium key with the vestigial _aes OID
            SubjectPublicKeyInfo aesSpki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(aesOid), dilithiumSpki.getPublicKeyData().getOctets());
            PrivateKeyInfo aesPki = new PrivateKeyInfo(
                new AlgorithmIdentifier(aesOid), dilithiumPki.parsePrivateKey());

            // core factories: both sides reject. Previously the public side built a key
            // with null parameters (no exception) while the private side threw, so the
            // "public side rejects" assertion below fails without the fix.
            try
            {
                PublicKeyFactory.createKey(aesSpki);
                fail("PublicKeyFactory should reject vestigial " + aesOid);
            }
            catch (Exception e)
            {
                // expected: IOException "algorithm identifier in public key not recognised: ..."
            }

            try
            {
                PrivateKeyFactory.createKey(aesPki);
                fail("PrivateKeyFactory should reject vestigial " + aesOid);
            }
            catch (Exception e)
            {
                // expected: RuntimeException "algorithm identifier in private key not recognised"
            }

            // BC bridge: no converter registered for the _aes OIDs, so both return null.
            assertNull("getPublicKey " + aesOid, BouncyCastleProvider.getPublicKey(aesSpki));
            assertNull("getPrivateKey " + aesOid, BouncyCastleProvider.getPrivateKey(aesPki));
        }
    }
}
