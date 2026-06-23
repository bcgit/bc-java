package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.generators.CMCEKeyPairGenerator;
import org.bouncycastle.crypto.kems.CMCEKEMExtractor;
import org.bouncycastle.crypto.kems.CMCEKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.CMCEKeyGenerationParameters;
import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.crypto.params.CMCEPrivateKeyParameters;
import org.bouncycastle.crypto.params.CMCEPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * Known-answer tests for the standardised Classic McEliece KEM (ISO/IEC 18033-2:2006/Amd 2:2026,
 * Clause 13) under org.bouncycastle.crypto. Drives the public lightweight API
 * (CMCEKeyPairGenerator / CMCEKEMGenerator / CMCEKEMExtractor) with a deterministic NISTSecureRandom
 * through the shared TestUtils.testTestVector harness. (The harness's optional factory round-trip uses
 * the pqc-side org.bouncycastle.pqc.crypto.util factories, which do not handle these crypto-side keys,
 * so it is left off here; the id-kem-cm OID round-trip through org.bouncycastle.crypto.util is covered
 * by the prov CMCEKEMTest. The legacy pqc engine is covered separately by CMCEVectorTest.)
 * <p>
 * The non-pc and "f" sets reuse the official KAT vectors already staged under pqc/crypto/cmce (the
 * standardised engine is byte-identical to the legacy one for these sets). The pc/pcf vectors were
 * generated from the official Classic McEliece reference (libmceliece, lib.mceliece.org) driven by the
 * NIST CTR-DRBG so they reproduce here - validated by regenerating the non-pc/f sets byte-identically
 * against the existing KATs - and staged alongside as *-pc-cmce.rsp / *-pcf-cmce.rsp.
 */
public class CMCEKEMVectorTest
    extends TestCase
{
    private static final CMCEParameters[] PARAMETER_SETS = new CMCEParameters[]{
        CMCEParameters.mceliece460896, CMCEParameters.mceliece460896f, CMCEParameters.mceliece460896pc, CMCEParameters.mceliece460896pcf,
        CMCEParameters.mceliece6688128, CMCEParameters.mceliece6688128f, CMCEParameters.mceliece6688128pc, CMCEParameters.mceliece6688128pcf,
        CMCEParameters.mceliece6960119, CMCEParameters.mceliece6960119f, CMCEParameters.mceliece6960119pc, CMCEParameters.mceliece6960119pcf,
        CMCEParameters.mceliece8192128, CMCEParameters.mceliece8192128f, CMCEParameters.mceliece8192128pc, CMCEParameters.mceliece8192128pcf
    };

    private static final String[] files = new String[]{
        "4608-96-cmce.rsp", "4608-96-f-cmce.rsp", "4608-96-pc-cmce.rsp", "4608-96-pcf-cmce.rsp",
        "6688-128-cmce.rsp", "6688-128-f-cmce.rsp", "6688-128-pc-cmce.rsp", "6688-128-pcf-cmce.rsp",
        "6960-119-cmce.rsp", "6960-119-f-cmce.rsp", "6960-119-pc-cmce.rsp", "6960-119-pcf-cmce.rsp",
        "8192-128-cmce.rsp", "8192-128-f-cmce.rsp", "8192-128-pc-cmce.rsp", "8192-128-pcf-cmce.rsp"
    };

    public void testParameters()
        throws Exception
    {
        // every standardised set produces a 256-bit (32-byte) session key
        assertEquals(256, CMCEParameters.mceliece460896.getSessionKeySize());
        assertEquals(256, CMCEParameters.mceliece460896pcf.getSessionKeySize());
        assertEquals(256, CMCEParameters.mceliece6960119pc.getSessionKeySize());
        assertEquals(256, CMCEParameters.mceliece8192128.getSessionKeySize());
    }

    public void testKeyInfoFactoryRoundTrip()
        throws Exception
    {
        // Encode and decode the standardised keys through the org.bouncycastle.crypto.util factories,
        // confirming the SubjectPublicKeyInfo / PKCS#8 carries the per-parameter-set id-kem-cm OID and
        // that the key material survives the round-trip. The 460896 family covers the base/f/pc/pcf OID
        // suffixes; the remaining security levels exercise the same factories through prov CMCEKEMTest.
        CMCEParameters[] params = new CMCEParameters[]{
            CMCEParameters.mceliece460896, CMCEParameters.mceliece460896f,
            CMCEParameters.mceliece460896pc, CMCEParameters.mceliece460896pcf
        };
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]{
            ISOIECObjectIdentifiers.mceliece460896, ISOIECObjectIdentifiers.mceliece460896f,
            ISOIECObjectIdentifiers.mceliece460896pc, ISOIECObjectIdentifiers.mceliece460896pcf
        };

        for (int i = 0; i != params.length; i++)
        {
            CMCEKeyPairGenerator kpGen = new CMCEKeyPairGenerator();
            kpGen.init(new CMCEKeyGenerationParameters(new SecureRandom(), params[i]));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            CMCEPublicKeyParameters pub = (CMCEPublicKeyParameters)kp.getPublic();
            CMCEPrivateKeyParameters priv = (CMCEPrivateKeyParameters)kp.getPrivate();

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub);
            assertEquals(oids[i], spki.getAlgorithm().getAlgorithm());

            CMCEPublicKeyParameters pub2 = (CMCEPublicKeyParameters)PublicKeyFactory.createKey(spki);
            assertEquals(params[i], pub2.getParameters());
            assertTrue(Arrays.areEqual(pub.getPublicKey(), pub2.getPublicKey()));

            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(priv);
            assertEquals(oids[i], pki.getPrivateKeyAlgorithm().getAlgorithm());

            CMCEPrivateKeyParameters priv2 = (CMCEPrivateKeyParameters)PrivateKeyFactory.createKey(pki);
            assertEquals(params[i], priv2.getParameters());
            assertTrue(Arrays.areEqual(priv.getPrivateKey(), priv2.getPrivateKey()));
        }
    }

    public void testVectors()
        throws Exception
    {
        TestUtils.testTestVector(false, false, "pqc/crypto/cmce", files, new TestUtils.KeyEncapsulationOperation()
        {
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                CMCEKeyPairGenerator kpGen = new CMCEKeyPairGenerator();
                kpGen.init(new CMCEKeyGenerationParameters(random, PARAMETER_SETS[fileIndex]));
                return kpGen;
            }

            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((CMCEPublicKeyParameters)pubParams).getPublicKey();
            }

            public byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams)
            {
                return ((CMCEPrivateKeyParameters)privParams).getPrivateKey();
            }

            public EncapsulatedSecretGenerator getKEMGenerator(SecureRandom random)
            {
                return new CMCEKEMGenerator(random);
            }

            public EncapsulatedSecretExtractor getKEMExtractor(AsymmetricKeyParameter privParams)
            {
                return new CMCEKEMExtractor((CMCEPrivateKeyParameters)privParams);
            }

            public int getSessionKeySize()
            {
                return 0;
            }
        });
    }
}
