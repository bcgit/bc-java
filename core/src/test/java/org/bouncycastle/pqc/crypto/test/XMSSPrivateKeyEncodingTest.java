package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * PKCS#8 PrivateKeyInfo round-trip coverage for XMSS / XMSS^MT (github #2176). Every standard
 * (RFC 8391 / SP 800-208) parameter set is now encoded in the RFC 9802 form (id-alg-xmss-hashsig /
 * id-alg-xmssmt-hashsig) that the matching SubjectPublicKeyInfo uses, so a keypair's private and
 * public halves share one algorithm OID and a private key round-trips to its exact parameter set.
 * <p>
 * Before the fix, the SP 800-208 sets either threw during encoding (SHAKE256-LEN, unknown to the
 * legacy tree-digest table) or silently round-tripped to a different set (SHA-256/192, which shares
 * id-sha256 with the RFC 8391 SHA-256/256 set and lost n=24), and every set's private key carried
 * the legacy PQCObjectIdentifiers.xmss(_mt) OID rather than the public key's RFC 9802 OID.
 */
public class XMSSPrivateKeyEncodingTest
    extends TestCase
{
    // RFC 8391 sets.
    private static final int XMSS_SHA2_10_256 = 0x00000001;    // SHA-256/256, n=32
    private static final int XMSSMT_SHA2_20_2_256 = 0x00000001; // SHA-256/256, 20/2, n=32

    // SP 800-208 sets.
    private static final int XMSS_SHA2_10_192 = 0x0000000d;    // SHA-256/192, n=24
    private static final int XMSS_SHAKE256_10_192 = 0x00000013; // SHAKE256/192, n=24, id-shake256-len
    private static final int XMSSMT_SHA2_20_2_192 = 0x00000021;    // SHA-256/192, n=24
    private static final int XMSSMT_SHAKE256_20_2_192 = 0x00000031; // SHAKE256/192, n=24, id-shake256-len

    public void testXmssRfc8391SetSharesRfc9802Oid()
        throws Exception
    {
        checkXmss(XMSS_SHA2_10_256, 32);
    }

    public void testXmssSha256_192PrivateKeyRoundTrip()
        throws Exception
    {
        checkXmss(XMSS_SHA2_10_192, 24);
    }

    public void testXmssShake256_192PrivateKeyRoundTrip()
        throws Exception
    {
        checkXmss(XMSS_SHAKE256_10_192, 24);
    }

    public void testXmssMtRfc8391SetSharesRfc9802Oid()
        throws Exception
    {
        checkXmssMt(XMSSMT_SHA2_20_2_256, 32);
    }

    public void testXmssMtSha256_192PrivateKeyRoundTrip()
        throws Exception
    {
        checkXmssMt(XMSSMT_SHA2_20_2_192, 24);
    }

    public void testXmssMtShake256_192PrivateKeyRoundTrip()
        throws Exception
    {
        checkXmssMt(XMSSMT_SHAKE256_20_2_192, 24);
    }

    private void checkXmss(int paramSetOID, int expectedN)
        throws Exception
    {
        XMSSParameters params = XMSSParameters.lookupByOID(paramSetOID);
        assertNotNull("no XMSS parameter set for OID " + paramSetOID, params);
        assertEquals(expectedN, params.getTreeDigestSize());

        XMSSKeyPairGenerator gen = new XMSSKeyPairGenerator();
        gen.init(new XMSSKeyGenerationParameters(params, new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        XMSSPrivateKeyParameters priv = (XMSSPrivateKeyParameters)kp.getPrivate();

        PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(priv);

        // private key shares the RFC 9802 OID the public key uses (no OID divergence)
        assertEquals(IANAObjectIdentifiers.id_alg_xmss_hashsig, pkInfo.getPrivateKeyAlgorithm().getAlgorithm());
        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic());
        assertEquals(IANAObjectIdentifiers.id_alg_xmss_hashsig, spkInfo.getAlgorithm().getAlgorithm());

        // private key round-trips losslessly to the same parameter set
        XMSSPrivateKeyParameters recovered = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(pkInfo);
        assertEquals(paramSetOID, recovered.getParameters().getParameterSetOID());
        assertEquals(expectedN, recovered.getParameters().getTreeDigestSize());
        assertTrue(Arrays.areEqual(priv.getEncoded(), recovered.getEncoded()));
    }

    private void checkXmssMt(int paramSetOID, int expectedN)
        throws Exception
    {
        XMSSMTParameters params = XMSSMTParameters.lookupByOID(paramSetOID);
        assertNotNull("no XMSS^MT parameter set for OID " + paramSetOID, params);
        assertEquals(expectedN, params.getTreeDigestSize());

        XMSSMTKeyPairGenerator gen = new XMSSMTKeyPairGenerator();
        gen.init(new XMSSMTKeyGenerationParameters(params, new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        XMSSMTPrivateKeyParameters priv = (XMSSMTPrivateKeyParameters)kp.getPrivate();

        PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(priv);

        assertEquals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig, pkInfo.getPrivateKeyAlgorithm().getAlgorithm());
        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic());
        assertEquals(IANAObjectIdentifiers.id_alg_xmssmt_hashsig, spkInfo.getAlgorithm().getAlgorithm());

        XMSSMTPrivateKeyParameters recovered = (XMSSMTPrivateKeyParameters)PrivateKeyFactory.createKey(pkInfo);
        assertEquals(paramSetOID, recovered.getParameters().getParameterSetOID());
        assertEquals(expectedN, recovered.getParameters().getTreeDigestSize());
        assertTrue(Arrays.areEqual(priv.getEncoded(), recovered.getEncoded()));
    }
}
