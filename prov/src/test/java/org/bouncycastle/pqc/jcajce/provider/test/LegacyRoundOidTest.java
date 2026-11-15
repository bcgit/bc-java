package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Bouncy Castle 1.81 to 1.87 identified the NIST additional-signature parameter sets by OIDs without
 * the round suffix they now carry. Keys and signatures under those OIDs must still be read through the
 * JCA, and keys read that way must be written under the current OID.
 */
public class LegacyRoundOidTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testSnova()
        throws Exception
    {
        checkLegacyOid("SNOVA_24_5_4_SSK", BCObjectIdentifiers.snova_24_5_4_ssk, BCObjectIdentifiers.snova.branch("1"));
    }

    public void testSDitH()
        throws Exception
    {
        checkLegacyOid("SDITH-HYPERCUBE-CAT1-GF256", BCObjectIdentifiers.sdith_hypercube_cat1_gf256,
            BCObjectIdentifiers.sdith.branch("1"));
    }

    private void checkLegacyOid(String name, ASN1ObjectIdentifier current, ASN1ObjectIdentifier legacy)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        byte[] pubEnc = kp.getPublic().getEncoded();
        byte[] privEnc = kp.getPrivate().getEncoded();
        assertEquals(current, SubjectPublicKeyInfo.getInstance(pubEnc).getAlgorithm().getAlgorithm());
        assertEquals(current, PrivateKeyInfo.getInstance(privEnc).getPrivateKeyAlgorithm().getAlgorithm());

        byte[] legacyPubEnc = withAlgorithm(pubEnc, 0, legacy);
        byte[] legacyPrivEnc = withAlgorithm(privEnc, 1, legacy);

        // the parameter-set and generic key factories, and the factory named by the legacy OID
        String[] factoryNames = new String[]{ name, legacy.getId() };
        for (int i = 0; i != factoryNames.length; i++)
        {
            KeyFactory kf = KeyFactory.getInstance(factoryNames[i], "BCPQC");

            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(legacyPubEnc));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(legacyPrivEnc));

            assertTrue(factoryNames[i] + ": public key not written under the current OID",
                Arrays.areEqual(pubEnc, pub.getEncoded()));
            assertTrue(factoryNames[i] + ": private key not written under the current OID",
                Arrays.areEqual(privEnc, priv.getEncoded()));
        }

        // the BC provider bridge, as used for certificates
        PublicKey bcPub = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(legacyPubEnc));
        PrivateKey bcPriv = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(legacyPrivEnc));
        assertNotNull(bcPub);
        assertNotNull(bcPriv);
        assertTrue(Arrays.areEqual(pubEnc, bcPub.getEncoded()));
        assertTrue(Arrays.areEqual(privEnc, bcPriv.getEncoded()));

        // a signature identified by the legacy OID, as in a certificate made by an earlier release
        byte[] msg = Strings.toByteArray("legacy round OID");
        Signature signer = Signature.getInstance(name, "BCPQC");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(legacy.getId(), "BCPQC");
        verifier.initVerify(bcPub);
        verifier.update(msg);
        assertTrue(verifier.verify(sig));
    }

    private static byte[] withAlgorithm(byte[] keyInfo, int algIndex, ASN1ObjectIdentifier algOID)
        throws Exception
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo);
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i != seq.size(); i++)
        {
            v.add(i == algIndex ? new AlgorithmIdentifier(algOID) : seq.getObjectAt(i));
        }
        return new DERSequence(v).getEncoded();
    }
}
