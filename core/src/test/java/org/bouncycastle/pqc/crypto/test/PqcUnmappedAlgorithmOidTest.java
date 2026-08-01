package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.legacy.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.legacy.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.legacy.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.legacy.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;

/**
 * Regression tests for the algorithm-identifier dispatch in the PQC {@link PrivateKeyFactory} /
 * {@link PublicKeyFactory}.
 * <p>
 * The private-key dispatch used to select a branch with {@code algOID.on(&lt;arc&gt;)}, a subtree
 * test that matches <i>every</i> leaf below the arc — including leaves that have no entry in the
 * matching {@code Utils.*Params} table. The branch then passed the {@code null} lookup result
 * straight into a {@code *PrivateKeyParameters} constructor, so a PKCS#8 blob naming such an OID
 * escaped {@code createKey} with a {@link NullPointerException} (or, where the constructor merely
 * stores the parameters, returned a key object carrying {@code null} parameters that failed later,
 * far from the parse). Both are wrong for a method whose contract is {@code throws IOException}.
 * <p>
 * The concrete reported case is the OQS interop arc 1.3.9999.6, which carries 16 <i>hybrid</i>
 * (ECDSA-P256 / RSA-3072 / P-384 / P-521 combined with SPHINCS+) OIDs that are declared in
 * {@link BCObjectIdentifiers} but deliberately not implemented — e.g.
 * {@code p256_sphincs_sha2_128f_simple} = 1.3.9999.6.4.14.
 */
public class PqcUnmappedAlgorithmOidTest
    extends TestCase
{
    /**
     * The 16 OQS hybrid OIDs under 1.3.9999.6: declared in BCObjectIdentifiers, deliberately not
     * implemented, and matched by {@code algOID.on(sphincsPlus_interop)}.
     */
    private static final ASN1ObjectIdentifier[] OQS_HYBRID_OIDS = new ASN1ObjectIdentifier[]
    {
        BCObjectIdentifiers.p256_sphincs_sha2_128f_simple,
        BCObjectIdentifiers.rsa_3072_sphincs_sha2_128f_simple,
        BCObjectIdentifiers.p256_sphincs_sha2_128s_simple,
        BCObjectIdentifiers.rsa_3072_sphincs_sha2_128s_simple,
        BCObjectIdentifiers.p384_sphincs_sha2_192f_simple,
        BCObjectIdentifiers.p384_sphincs_sha2192s_simple,
        BCObjectIdentifiers.p521_sphincs_sha2_256f_simple,
        BCObjectIdentifiers.p521_sphincs_sha2_256s_simple,
        BCObjectIdentifiers.p256_sphincs_shake_128f_simple,
        BCObjectIdentifiers.rsa_3072_sphincs_shake_128f_simple,
        BCObjectIdentifiers.p256_sphincs_shake_128s_simple,
        BCObjectIdentifiers.rsa_3072_sphincs_shake_128s_simple,
        BCObjectIdentifiers.p384_sphincs_shake_192f_simple,
        BCObjectIdentifiers.p384_sphincs_shake_192s_simple,
        BCObjectIdentifiers.p521_sphincs_shake256f_simple,
        BCObjectIdentifiers.p521_sphincs_shake256s_simple,
    };

    /**
     * Every arc the private-key dispatch used to select with {@code algOID.on(arc)}. An arbitrary
     * undeclared leaf below each of these is matched by the subtree test but has no parameters.
     */
    private static final ASN1ObjectIdentifier[] DISPATCH_ARCS = new ASN1ObjectIdentifier[]
    {
        BCObjectIdentifiers.sphincsPlus,
        BCObjectIdentifiers.sphincsPlus_interop,
        BCObjectIdentifiers.pqc_kem_mceliece,
        BCObjectIdentifiers.pqc_kem_saber,
        BCObjectIdentifiers.pqc_kem_ntru,
        BCObjectIdentifiers.pqc_kem_ntrulprime,
        BCObjectIdentifiers.pqc_kem_sntruprime,
        BCObjectIdentifiers.pqc_kem_bike,
        BCObjectIdentifiers.pqc_kem_hqc,
        BCObjectIdentifiers.snova,
        BCObjectIdentifiers.hawk,
        BCObjectIdentifiers.pqc_kem_ntruplus,
        BCObjectIdentifiers.aimer,
        BCObjectIdentifiers.pqc_kem_smaugt,
        BCObjectIdentifiers.faest,
        BCObjectIdentifiers.qruov,
        BCObjectIdentifiers.sqisign,
        BCObjectIdentifiers.haetae,
    };

    /**
     * Private-key bodies covering the shapes the various branches parse before (or instead of)
     * reaching the parameters lookup: a bare OCTET STRING, a CMCEPrivateKey-shaped SEQUENCE, and
     * an NTRU-Prime-shaped SEQUENCE of OCTET STRINGs.
     */
    private static ASN1Encodable[] privateKeyBodies()
    {
        return new ASN1Encodable[]
        {
            new DEROctetString(new byte[64]),
            new DERSequence(new ASN1Encodable[]
            {
                new ASN1Integer(0), new DEROctetString(new byte[32]), new DEROctetString(new byte[32]),
                new DEROctetString(new byte[32]), new DEROctetString(new byte[32]), new DEROctetString(new byte[32])
            }),
            new DERSequence(new ASN1Encodable[]
            {
                new DEROctetString(new byte[32]), new DEROctetString(new byte[32]),
                new DEROctetString(new byte[32]), new DEROctetString(new byte[32]),
                new DEROctetString(new byte[32])
            }),
        };
    }

    /**
     * The reported case: a PKCS#8 PrivateKeyInfo tagged with the OQS hybrid OID 1.3.9999.6.4.14
     * used to leave createKey as a NullPointerException.
     */
    public void testOqsHybridP256Sphincs128fPrivateKeyRejected()
        throws Exception
    {
        ASN1ObjectIdentifier algOID = BCObjectIdentifiers.p256_sphincs_sha2_128f_simple;

        assertEquals("1.3.9999.6.4.14", algOID.getId());
        assertTrue("test premise: OID is matched by the OQS interop subtree",
            algOID.on(BCObjectIdentifiers.sphincsPlus_interop));

        PrivateKeyInfo keyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(algOID),
            new DEROctetString(new byte[64]));

        try
        {
            PrivateKeyFactory.createKey(keyInfo.getEncoded());
            fail("no exception for unmapped OQS hybrid OID");
        }
        catch (IOException e)
        {
            // expected: the declared contract
        }
    }

    /**
     * All 16 OQS hybrid OIDs, over every private-key body shape.
     */
    public void testOqsHybridPrivateKeysRejected()
        throws Exception
    {
        for (int i = 0; i != OQS_HYBRID_OIDS.length; i++)
        {
            assertUnmappedPrivateKeyRejected(OQS_HYBRID_OIDS[i]);
        }
    }

    /**
     * The general form: an undeclared leaf under each arc the dispatch used to accept wholesale.
     */
    public void testUndeclaredLeafUnderEachDispatchArcRejected()
        throws Exception
    {
        for (int i = 0; i != DISPATCH_ARCS.length; i++)
        {
            assertUnmappedPrivateKeyRejected(DISPATCH_ARCS[i].branch("9999"));
        }
    }

    private void assertUnmappedPrivateKeyRejected(ASN1ObjectIdentifier algOID)
        throws Exception
    {
        ASN1Encodable[] bodies = privateKeyBodies();

        for (int i = 0; i != bodies.length; i++)
        {
            PrivateKeyInfo keyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(algOID), bodies[i]);

            try
            {
                PrivateKeyFactory.createKey(keyInfo.getEncoded());
                fail("no exception for unmapped OID " + algOID + " (body " + i + ")");
            }
            catch (IOException e)
            {
                // expected: the declared contract
            }
            catch (RuntimeException e)
            {
                fail("RuntimeException past declared throws for unmapped OID " + algOID
                    + " (body " + i + "): " + e);
            }
        }
    }

    /**
     * Public-key side. The 16 hybrid OIDs are not in the PublicKeyFactory converter table at all,
     * so they were already rejected cleanly; the leak there came from converter registrations
     * whose OID has no entry in the matching parameters table — the bare SPHINCS+ arc, the OQS
     * round-3 OID 1.3.9999.6.4.10, and the vestigial Kyber-AES OIDs.
     */
    public void testUnbackedPublicKeyRegistrationsRejected()
        throws Exception
    {
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]
        {
            BCObjectIdentifiers.sphincsPlus,                      // bare arc, never a parameter set
            new ASN1ObjectIdentifier("1.3.9999.6.4.10"),          // OQS round-3 SPHINCS+ OID
            BCObjectIdentifiers.kyber512_aes,
            BCObjectIdentifiers.kyber768_aes,
            BCObjectIdentifiers.kyber1024_aes,
        };

        for (int i = 0; i != oids.length; i++)
        {
            SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(oids[i]), new byte[64]);

            try
            {
                PublicKeyFactory.createKey(keyInfo.getEncoded());
                fail("no exception for unbacked public key OID " + oids[i]);
            }
            catch (IOException e)
            {
                // expected: the declared contract
            }
            catch (RuntimeException e)
            {
                fail("RuntimeException past declared throws for unbacked public key OID "
                    + oids[i] + ": " + e);
            }
        }
    }

    /**
     * Compatibility assertion and drift guard in one. Every OID declared in BCObjectIdentifiers
     * below one of the dispatch arcs must either still reach its branch, or be one of the 16
     * known-unimplemented OQS hybrids. A declared OID that stops dispatching means the narrowed
     * predicate cut too deep; a newly declared OID with no parameters table entry shows up here as
     * an unexpected "not recognised", which is exactly the drift that produced this defect.
     */
    public void testDeclaredOidsUnderDispatchArcsStillDispatch()
        throws Exception
    {
        Set expectedUnmapped = new HashSet();
        for (int i = 0; i != OQS_HYBRID_OIDS.length; i++)
        {
            expectedUnmapped.add(OQS_HYBRID_OIDS[i].getId());
        }

        List unexpectedUnmapped = new ArrayList();
        int dispatched = 0;

        Field[] fields = BCObjectIdentifiers.class.getDeclaredFields();
        for (int f = 0; f != fields.length; f++)
        {
            if (!ASN1ObjectIdentifier.class.isAssignableFrom(fields[f].getType()))
            {
                continue;
            }

            ASN1ObjectIdentifier algOID = (ASN1ObjectIdentifier)fields[f].get(null);
            if (!isUnderDispatchArc(algOID))
            {
                continue;
            }

            if (isRejectedAsUnrecognised(algOID))
            {
                if (!expectedUnmapped.contains(algOID.getId()))
                {
                    unexpectedUnmapped.add(fields[f].getName() + " (" + algOID + ")");
                }
            }
            else
            {
                dispatched++;
            }
        }

        assertTrue("declared OIDs under a dispatch arc no longer recognised: " + unexpectedUnmapped,
            unexpectedUnmapped.isEmpty());
        assertTrue("expected a substantial set of mapped OIDs to still dispatch, got " + dispatched,
            dispatched > 100);
    }

    private static boolean isUnderDispatchArc(ASN1ObjectIdentifier algOID)
    {
        for (int i = 0; i != DISPATCH_ARCS.length; i++)
        {
            if (algOID.on(DISPATCH_ARCS[i]))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * True when every body shape is turned away as an unrecognised algorithm identifier - i.e. the
     * OID reaches no branch at all, as opposed to reaching one and failing on the bogus key body.
     */
    private static boolean isRejectedAsUnrecognised(ASN1ObjectIdentifier algOID)
        throws IOException
    {
        ASN1Encodable[] bodies = privateKeyBodies();

        for (int i = 0; i != bodies.length; i++)
        {
            PrivateKeyInfo keyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(algOID), bodies[i]);

            try
            {
                PrivateKeyFactory.createKey(keyInfo.getEncoded());
                return false;
            }
            catch (Exception e)
            {
                String msg = e.getMessage();
                if (msg == null || msg.indexOf("not recognised") < 0)
                {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * End-to-end compatibility on the arc that carries the reported hybrids: a real SPHINCS+ key
     * whose OID (1.3.9999.6.4.13) is a sibling leaf of 1.3.9999.6.4.14 must still round-trip.
     */
    public void testOqsInteropArcRealKeyStillRoundTrips()
        throws Exception
    {
        SPHINCSPlusKeyPairGenerator kpGen = new SPHINCSPlusKeyPairGenerator();
        kpGen.init(new SPHINCSPlusKeyGenerationParameters(new SecureRandom(), SPHINCSPlusParameters.sha2_128f));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        SPHINCSPlusPrivateKeyParameters priv = (SPHINCSPlusPrivateKeyParameters)kp.getPrivate();

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(priv);

        assertEquals("test premise: encoded under the OQS interop arc",
            BCObjectIdentifiers.sphincsPlus_sha2_128f, keyInfo.getPrivateKeyAlgorithm().getAlgorithm());
        assertTrue("test premise: sibling leaf of the reported hybrid OID",
            keyInfo.getPrivateKeyAlgorithm().getAlgorithm().on(BCObjectIdentifiers.sphincsPlus_interop));

        SPHINCSPlusPrivateKeyParameters decoded =
            (SPHINCSPlusPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo.getEncoded());

        assertEquals(priv.getParameters(), decoded.getParameters());
        assertTrue(Arrays.areEqual(priv.getEncoded(), decoded.getEncoded()));
    }
}
