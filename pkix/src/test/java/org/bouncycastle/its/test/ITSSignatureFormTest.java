package org.bouncycastle.its.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSImplicitCertificateBuilder;
import org.bouncycastle.its.ITSValidityPeriod;
import org.bouncycastle.its.bc.BcITSContentSigner;
import org.bouncycastle.its.bc.BcITSContentVerifierProvider;
import org.bouncycastle.its.bc.BcITSExplicitCertificateBuilder;
import org.bouncycastle.its.bc.BcITSImplicitCertificateBuilder;
import org.bouncycastle.its.bc.BcITSPublicVerificationKey;
import org.bouncycastle.its.jcajce.JcaITSContentSigner;
import org.bouncycastle.its.jcajce.JcaITSContentVerifierProvider;
import org.bouncycastle.its.jcajce.JcaITSImplicitCertificateBuilderBuilder;
import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CrlSeries;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP256Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP384Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Hostname;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point256;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point384;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SubjectAssurance;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

/**
 * IEEE 1609.2 (EcdsaP256Signature, EcdsaP384Signature) lets a signer carry r as rSig of form x-only, or the
 * point R as compressed-y-0, compressed-y-1 or uncompressed "at the sender's discretion", and requires rSig to be
 * taken to be of form x-only whenever the structure is encoded for hashing. These tests re-encode real signatures
 * with the actual point R, so every form is one a conformant signer could have produced.
 */
public class ITSSignatureFormTest
    extends TestCase
{
    private static final String certContentRoot = "/org/bouncycastle/its/certs";

    private static final int COMPRESSED = 0;
    private static final int UNCOMPRESSED = 1;

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * The ETSI conformance AA certificate, re-encoded with R, must still verify under the RCA, must still have the
     * HashedId8 the AT certificate names it by, and must still verify the AT certificate's signature, which covers
     * the hash of the AA certificate.
     */
    public void testConformanceChainWithPointR()
        throws Exception
    {
        ITSCertificate rca = loadCert("CERT_IUT_A_RCA.oer");
        ITSCertificate aa = loadCert("CERT_IUT_A_AA.oer");
        ITSCertificate at = loadCert("CERT_IUT_A_AT.oer");

        byte[] aaId = Hex.decode("34556d34931e5e5c");
        assertTrue("Arrays.areEqual(aaId, issuerId(at))", Arrays.areEqual(aaId, issuerId(at)));
        assertTrue("Arrays.areEqual(aaId, hashedId8(aa.getEncoded(), new SHA256Digest()))", Arrays.areEqual(aaId, hashedId8(aa.getEncoded(), new SHA256Digest())));

        // x-only certificates hash exactly as encoded
        assertTrue("Arrays.areEqual(aa.getEncoded(), aa.getCanonicalEncoding())", Arrays.areEqual(aa.getEncoded(), aa.getCanonicalEncoding()));

        ECPoint r = recoverR(aa, rca);

        for (int form = COMPRESSED; form <= UNCOMPRESSED; form++)
        {
            ITSCertificate aaR = withPointR(aa, r, form);

            assertTrue("aaR.isSignatureValid(bc(rca))", aaR.isSignatureValid(new BcITSContentVerifierProvider(rca)));
            assertTrue("aaR.isSignatureValid(jca(rca))", aaR.isSignatureValid(new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(rca)));

            assertFalse("Arrays.areEqual(aaId, hashedId8(aaR.getEncoded(), new SHA256Digest()))", Arrays.areEqual(aaId, hashedId8(aaR.getEncoded(), new SHA256Digest())));
            assertTrue("Arrays.areEqual(aaId, hashedId8(aaR.getCanonicalEncoding(), new SHA256Digest()))", Arrays.areEqual(aaId, hashedId8(aaR.getCanonicalEncoding(), new SHA256Digest())));
            assertTrue("Arrays.areEqual(aa.getEncoded(), aaR.getCanonicalEncoding())", Arrays.areEqual(aa.getEncoded(), aaR.getCanonicalEncoding()));

            assertTrue("at.isSignatureValid(bc(aaR))", at.isSignatureValid(new BcITSContentVerifierProvider(aaR)));
            assertTrue("at.isSignatureValid(jca(aaR))", at.isSignatureValid(new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(aaR)));

            // an implicit certificate issued under the re-encoded AA certificate names it by its x-only HashedId8
            ITSCertificate bcImplicit = issueImplicit(new BcITSImplicitCertificateBuilder(aaR, newTbsBuilder()));
            assertTrue("Arrays.areEqual(aaId, issuerId(bcImplicit))", Arrays.areEqual(aaId, issuerId(bcImplicit)));
            ITSCertificate jcaImplicit = issueImplicit(
                new JcaITSImplicitCertificateBuilderBuilder().setProvider("BC").build(aaR, newTbsBuilder()));
            assertTrue("Arrays.areEqual(aaId, issuerId(jcaImplicit))", Arrays.areEqual(aaId, issuerId(jcaImplicit)));
        }
    }

    /**
     * The same for a generated brainpoolP384r1 hierarchy, covering the EcdsaP384Signature path, a self-signed
     * certificate, and the issuer HashedId8 BC writes into a certificate it issues.
     */
    public void testBrainpoolP384PointR()
        throws Exception
    {
        ASN1ObjectIdentifier curveID = TeleTrusTObjectIdentifiers.brainpoolP384r1;
        AsymmetricCipherKeyPair rootKp = generateKeyPair(curveID);
        AsymmetricCipherKeyPair caKp = generateKeyPair(curveID);
        AsymmetricCipherKeyPair eeKp = generateKeyPair(curveID);

        ITSCertificate root = issue(new BcITSContentSigner(privateKey(rootKp)), "root", rootKp);
        ITSCertificate ca = issue(new BcITSContentSigner(privateKey(rootKp), root), "ca", caKp);

        PrivateKey jcaCaKey = KeyFactory.getInstance("EC", "BC").generatePrivate(
            new PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey(caKp)).getEncoded()));

        ECPoint rootR = recoverR(root, null);
        ECPoint caR = recoverR(ca, root);

        for (int form = COMPRESSED; form <= UNCOMPRESSED; form++)
        {
            ITSCertificate rootRCert = withPointR(root, rootR, form);
            ITSCertificate caRCert = withPointR(ca, caR, form);

            assertTrue("rootRCert.isSignatureValid(bc(rootRCert))", rootRCert.isSignatureValid(new BcITSContentVerifierProvider(rootRCert)));
            assertTrue("rootRCert.isSignatureValid(jca(rootRCert))", rootRCert.isSignatureValid(new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(rootRCert)));

            // the CA certificate's signature covers the hash of the root certificate
            assertTrue("ca.isSignatureValid(bc(rootRCert))", ca.isSignatureValid(new BcITSContentVerifierProvider(rootRCert)));
            assertTrue("ca.isSignatureValid(jca(rootRCert))", ca.isSignatureValid(new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(rootRCert)));
            assertTrue("caRCert.isSignatureValid(bc(root))", caRCert.isSignatureValid(new BcITSContentVerifierProvider(root)));

            // a certificate issued under the re-encoded CA certificate names it by its x-only HashedId8
            ITSCertificate ee = issue(new BcITSContentSigner(privateKey(caKp), caRCert), "ee", eeKp);
            assertTrue("Arrays.areEqual(hashedId8(ca.getEncoded(), new SHA384Digest()), issuerId(ee))", Arrays.areEqual(hashedId8(ca.getEncoded(), new SHA384Digest()), issuerId(ee)));
            assertTrue("ee.isSignatureValid(bc(ca))", ee.isSignatureValid(new BcITSContentVerifierProvider(ca)));
            assertTrue("ee.isSignatureValid(jca(caRCert))", ee.isSignatureValid(new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(caRCert)));

            ITSCertificate jcaEe = issue(new JcaITSContentSigner.Builder().setProvider("BC").build(jcaCaKey, caRCert), "jca ee", eeKp);
            assertTrue("Arrays.areEqual(hashedId8(ca.getEncoded(), new SHA384Digest()), issuerId(jcaEe))", Arrays.areEqual(hashedId8(ca.getEncoded(), new SHA384Digest()), issuerId(jcaEe)));
            assertTrue("jcaEe.isSignatureValid(bc(ca))", jcaEe.isSignatureValid(new BcITSContentVerifierProvider(ca)));
        }
    }

    public void testFillRejected()
        throws Exception
    {
        ITSCertificate rca = loadCert("CERT_IUT_A_RCA.oer");
        ITSCertificate aa = loadCert("CERT_IUT_A_AA.oer");

        CertificateBase base = aa.toASN1Structure();
        EcdsaP256Signature sig = EcdsaP256Signature.getInstance(base.getSignature().getSignature());
        ITSCertificate aaFill = withSignature(aa, new Signature(base.getSignature().getChoice(),
            new EcdsaP256Signature(EccP256CurvePoint.fill(), sig.getSSig())));

        try
        {
            aaFill.isSignatureValid(new BcITSContentVerifierProvider(rca));
            fail("fill rSig accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("rSig choice 1 does not carry an r value", e.getMessage());
        }

        try
        {
            aaFill.getCanonicalEncoding();
            fail("fill rSig canonicalised");
        }
        catch (IOException e)
        {
            assertTrue(e.getCause() instanceof IllegalArgumentException);
        }
    }

    public void testXOnlyUnchanged()
        throws Exception
    {
        Signature sig = loadCert("CERT_IUT_A_AA.oer").toASN1Structure().getSignature();

        assertSame(sig, ECDSAEncoder.toXOnly(sig));
    }

    /**
     * Recover the point R behind a certificate's signature: R = (e/s)G + (r/s)Q, where e is the IEEE 1609.2 signing
     * input Hash(Hash(tbsCertificate) || Hash(issuer certificate)), the issuer hash being that of the empty string
     * for a self-signed certificate.
     */
    private static ECPoint recoverR(ITSCertificate cert, ITSCertificate issuer)
        throws IOException
    {
        ITSCertificate keyCert = (issuer == null) ? cert : issuer;
        PublicVerificationKey pvk = PublicVerificationKey.getInstance(
            keyCert.toASN1Structure().getToBeSigned().getVerifyKeyIndicator().getVerificationKeyIndicator());
        ECPublicKeyParameters q = (ECPublicKeyParameters)new BcITSPublicVerificationKey(pvk).getKey();

        Signature signature = cert.toASN1Structure().getSignature();
        boolean p384 = signature.getChoice() == Signature.ecdsaBrainpoolP384r1Signature;
        byte[] rs;
        byte[] ss;
        if (p384)
        {
            EcdsaP384Signature sig = EcdsaP384Signature.getInstance(signature.getSignature());
            rs = ASN1OctetString.getInstance(sig.getRSig().getEccP384CurvePoint()).getOctets();
            ss = sig.getSSig().getOctets();
        }
        else
        {
            EcdsaP256Signature sig = EcdsaP256Signature.getInstance(signature.getSignature());
            rs = ASN1OctetString.getInstance(sig.getRSig().getEccp256CurvePoint()).getOctets();
            ss = sig.getSSig().getOctets();
        }

        byte[] tbs = OEREncoder.toByteArray(cert.toASN1Structure().getToBeSigned(), IEEE1609dot2.ToBeSignedCertificate.build());
        byte[] parent = (issuer == null) ? new byte[0] : issuer.getEncoded();
        Digest digest = p384 ? (Digest)new SHA384Digest() : new SHA256Digest();
        BigInteger e = BigIntegers.fromUnsignedByteArray(hash(digest, Arrays.concatenate(hash(digest, tbs), hash(digest, parent))));

        BigInteger n = q.getParameters().getN();
        BigInteger sInv = BigIntegers.fromUnsignedByteArray(ss).modInverse(n);
        BigInteger r = BigIntegers.fromUnsignedByteArray(rs);
        ECPoint point = ECAlgorithms.sumOfTwoMultiplies(q.getParameters().getG(), e.multiply(sInv).mod(n),
            q.getQ(), r.multiply(sInv).mod(n)).normalize();

        assertEquals(r, point.getAffineXCoord().toBigInteger().mod(n));

        return point;
    }

    private static ITSCertificate withPointR(ITSCertificate cert, ECPoint r, int form)
    {
        Signature signature = cert.toASN1Structure().getSignature();
        byte[] enc = r.getEncoded(form == COMPRESSED);
        int len = (enc.length - 1) / ((form == COMPRESSED) ? 1 : 2);
        byte[] x = Arrays.copyOfRange(enc, 1, 1 + len);
        byte[] y = (form == COMPRESSED) ? null : Arrays.copyOfRange(enc, 1 + len, enc.length);
        int yChoice = (enc[0] == 0x02) ? EccP256CurvePoint.compressedY0 : EccP256CurvePoint.compressedY1;

        if (signature.getChoice() == Signature.ecdsaBrainpoolP384r1Signature)
        {
            EcdsaP384Signature sig = EcdsaP384Signature.getInstance(signature.getSignature());
            EccP384CurvePoint rSig = (form == COMPRESSED)
                ? new EccP384CurvePoint(yChoice, new DEROctetString(x))
                : EccP384CurvePoint.uncompressedP384(new Point384(new DEROctetString(x), new DEROctetString(y)));
            return withSignature(cert, new Signature(signature.getChoice(), new EcdsaP384Signature(rSig, sig.getSSig())));
        }

        EcdsaP256Signature sig = EcdsaP256Signature.getInstance(signature.getSignature());
        EccP256CurvePoint rSig = (form == COMPRESSED)
            ? new EccP256CurvePoint(yChoice, new DEROctetString(x))
            : EccP256CurvePoint.uncompressedP256(new Point256(new DEROctetString(x), new DEROctetString(y)));
        return withSignature(cert, new Signature(signature.getChoice(), new EcdsaP256Signature(rSig, sig.getSSig())));
    }

    private static ITSCertificate withSignature(ITSCertificate cert, Signature signature)
    {
        CertificateBase base = cert.toASN1Structure();

        return new ITSCertificate(new CertificateBase(base.getVersion(), base.getType(), base.getIssuer(),
            base.getToBeSigned(), signature));
    }

    private static byte[] issuerId(ITSCertificate cert)
    {
        return HashedId8.getInstance(cert.getIssuer().getIssuerIdentifier()).getHashBytes();
    }

    private static byte[] hashedId8(byte[] data, Digest digest)
    {
        byte[] h = hash(digest, data);

        return Arrays.copyOfRange(h, h.length - 8, h.length);
    }

    private static byte[] hash(Digest digest, byte[] data)
    {
        byte[] out = new byte[digest.getDigestSize()];
        digest.update(data, 0, data.length);
        digest.doFinal(out, 0);
        return out;
    }

    private static AsymmetricCipherKeyPair generateKeyPair(ASN1ObjectIdentifier curveID)
    {
        X9ECParameters parameters = TeleTrusTNamedCurves.getByOID(curveID);
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(curveID, parameters), new SecureRandom()));
        return generator.generateKeyPair();
    }

    private static ECPrivateKeyParameters privateKey(AsymmetricCipherKeyPair kp)
    {
        return (ECPrivateKeyParameters)kp.getPrivate();
    }

    private static ToBeSignedCertificate.Builder newTbsBuilder()
    {
        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();
        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        tbsBuilder.setCrlSeries(new CrlSeries(1));
        return tbsBuilder;
    }

    private static ITSCertificate issueImplicit(ITSImplicitCertificateBuilder builder)
    {
        builder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        return builder.build(CertificateId.name(new Hostname("implicit")), BigIntegers.ONE, BigIntegers.TWO);
    }

    private static ITSCertificate issue(ITSContentSigner signer, String name, AsymmetricCipherKeyPair subjectKp)
    {
        BcITSExplicitCertificateBuilder builder = new BcITSExplicitCertificateBuilder(signer, newTbsBuilder());
        builder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        return builder.build(CertificateId.name(new Hostname(name)), (ECPublicKeyParameters)subjectKp.getPublic());
    }

    private ITSCertificate loadCert(String name)
        throws IOException
    {
        InputStream src = this.getClass().getResourceAsStream(certContentRoot + "/" + name);
        if (src == null)
        {
            throw new IllegalStateException("unable to find test cert: " + name);
        }
        byte[] data = Streams.readAll(src);
        src.close();

        return new ITSCertificate(CertificateBase.getInstance(
            new OERInputStream(new ByteArrayInputStream(data)).parse(IEEE1609dot2.CertificateBase.build())));
    }
}
