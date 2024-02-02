package org.bouncycastle.its.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSExplicitCertificateBuilder;
import org.bouncycastle.its.ITSImplicitCertificateBuilder;
import org.bouncycastle.its.ITSPublicVerificationKey;
import org.bouncycastle.its.ITSValidityPeriod;
import org.bouncycastle.its.jcajce.JcaITSContentSigner;
import org.bouncycastle.its.jcajce.JcaITSContentVerifierProvider;
import org.bouncycastle.its.jcajce.JcaITSExplicitCertificateBuilder;
import org.bouncycastle.its.jcajce.JcaITSImplicitCertificateBuilderBuilder;
import org.bouncycastle.its.jcajce.JcaITSPublicVerificationKey;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.its.ieee1609dot2.Certificate;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.EndEntityType;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.PsidGroupPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.SequenceOfPsidGroupPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.SubjectPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.VerificationKeyIndicator;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.BitmapSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CrlSeries;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Hostname;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PsidSspRange;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSspRange;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ServiceSpecificPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SubjectAssurance;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

public class ITSJcaJceBasicTest
    extends TestCase
{
    public static void ensureProvider()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static ITSCertificate loadCertificate(byte[] data)
        throws Exception
    {
        ByteArrayInputStream fin = new ByteArrayInputStream(data);

        OERInputStream oi = new OERInputStream(fin);

//        OERInputStream oi = new OERInputStream(new HexIn(fin))
//        {
//            {
//                debugOutput = new PrintWriter(System.out);
//            }
//        };
        ASN1Object obj = oi.parse(IEEE1609dot2.Certificate.build());
        ITSCertificate certificate = new ITSCertificate(Certificate.getInstance(obj));
        fin.close();
        return certificate;
    }

    public void testImplicitBuilder()
        throws Exception
    {
        ensureProvider();

        byte[] ca = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        ITSCertificate caCert = loadCertificate(ca);


        byte[] parentData = caCert.getEncoded();
        Digest digest = SHA256Digest.newInstance();
        byte[] parentDigest = new byte[digest.getDigestSize()];

        digest.update(parentData, 0, parentData.length);

        digest.doFinal(parentDigest, 0);


        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();

        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        // builder.setCanRequestRollover(OEROptional.ABSENT);
        
        ITSImplicitCertificateBuilder certificateBuilder = new JcaITSImplicitCertificateBuilderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCert, tbsBuilder);

        certificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        certificateBuilder.setAppPermissions(
            PsidSsp.builder()
                .setPsid(new Psid(622))
                .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(Hex.decode("0101"))))
                .createPsidSsp(),
            PsidSsp.builder()
                .setPsid(new Psid(624))
                .setSsp(ServiceSpecificPermissions
                    .bitmapSsp(new BitmapSsp(Hex.decode("020138")))
                    )
                .createPsidSsp()); // App Permissions

        certificateBuilder.setCertIssuePermissions(
            PsidGroupPermissions.builder()
                .setSubjectPermissions(
                    SubjectPermissions.explicit(
                        SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(36).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(37).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(137).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(138).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(139).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(140).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                            .build()
                    ))
                .setMinChainLength(2)
                .setChainLengthRange(0)
                .setEeType(new EndEntityType(0xC0))
                .createPsidGroupPermissions(),
            PsidGroupPermissions.builder()
                .setSubjectPermissions(SubjectPermissions
                    .explicit(SequenceOfPsidSspRange.builder()
                        .add(PsidSspRange.builder()
                            .setPsid(623)
                            .createPsidSspRange())
                        .build())
                    )
                .setMinChainLength(1)
                .setChainLengthRange(0)
                .setEeType(new EndEntityType(0xC0)).createPsidGroupPermissions());

        ITSCertificate cert = certificateBuilder.build(
            CertificateId
                .name(new Hostname("Legion of the BouncyCastle CA")), BigInteger.ONE, BigIntegers.TWO, null);

        IssuerIdentifier caIssuerIdentifier = IssuerIdentifier
            .sha256AndDigest(new HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length)));

        assertTrue(cert.getIssuer().equals(caIssuerIdentifier));

        VerificationKeyIndicator vki = cert.toASN1Structure().getToBeSigned().getVerifyKeyIndicator();
        assertEquals(vki.getChoice(), VerificationKeyIndicator.reconstructionValue);
        assertEquals(vki.getVerificationKeyIndicator(), EccP256CurvePoint.uncompressedP256(BigInteger.ONE, BigIntegers.TWO));
    }

    public void testBuildSelfSigned()
        throws Exception
    {

        ensureProvider();

        JcaJceHelper helper = new ProviderJcaJceHelper(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));


        byte[] ca = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        ITSCertificate caCert = loadCertificate(ca);

        KeyPairGenerator kpg = helper.createKeyPairGenerator("ECDSA");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey publicVerificationKey = (ECPublicKey)kp.getPublic();
        ECPrivateKey privateKeyParameters = (ECPrivateKey)kp.getPrivate();


        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();
        tbsBuilder.setAppPermissions(
            SequenceOfPsidSsp.builder()
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(622))
                    .setSsp(ServiceSpecificPermissions
                        .bitmapSsp(new BitmapSsp(Hex.decode("0101"))))
                    .createPsidSsp())
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(624))
                    .setSsp(ServiceSpecificPermissions
                        .bitmapSsp(new BitmapSsp(Hex.decode("020138"))))
                    .createPsidSsp())
                .createSequenceOfPsidSsp()); // App Permissions
        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        // builder.setCanRequestRollover(OEROptional.ABSENT);
        tbsBuilder.setCertIssuePermissions(
            SequenceOfPsidGroupPermissions.builder()
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(
                        SubjectPermissions.explicit(
                            SequenceOfPsidSspRange.builder()
                                .add(PsidSspRange.builder()
                                    .setPsid(36).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(37).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(137).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(138).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(139).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(140).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                                .build()
                        ))
                    .setMinChainLength(2)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))

                    .createPsidGroupPermissions())
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(SubjectPermissions
                        .explicit(SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(623)
                                .createPsidSspRange())
                            .build())
                        )
                    .setMinChainLength(1)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))
                    .createPsidGroupPermissions())
                .createSequenceOfPsidGroupPermissions());

        tbsBuilder.setCrlSeries(new CrlSeries(1));

        ITSContentSigner itsContentSigner = new JcaITSContentSigner.Builder().build(privateKeyParameters);
        ITSExplicitCertificateBuilder itsCertificateBuilder = new JcaITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder);

        itsCertificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        ITSCertificate newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            new JcaITSPublicVerificationKey.Builder().build(publicVerificationKey));

        JcaITSContentVerifierProvider provider = new JcaITSContentVerifierProvider.Builder().build(newCert);
        boolean valid = newCert.isSignatureValid(provider);

        TestCase.assertTrue(valid);
    }

    public void testSelfSignedCA()
        throws Exception
    {
        ensureProvider();
        byte[] ca = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        ITSCertificate caCert = loadCertificate(ca);
        JcaITSContentVerifierProvider provider = new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(caCert);
        boolean valid = caCert.isSignatureValid(provider);
        TestCase.assertTrue(valid);

        ToBeSignedCertificate toBeSignedCertificate = caCert.toASN1Structure().getToBeSigned();
        VerificationKeyIndicator vki = toBeSignedCertificate.getVerifyKeyIndicator();
        provider = new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(new ITSPublicVerificationKey((PublicVerificationKey)vki.getVerificationKeyIndicator()));
        valid = caCert.isSignatureValid(provider);
        TestCase.assertTrue(valid);
    }

    public void testBasicVerification()
        throws Exception
    {
        ensureProvider();


        byte[] rootCertRaw = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        byte[] issuerRaw = Hex.decode("80030080c6f1125e19b175ee398300000000001a5617008466a88001018002026f810302013201012080010780012482080301fffc03ff0003800125820a0401ffffff04ff00000080018982060201e002ff1f80018a82060201c002ff3f80018b820e0601000000fff806ff000000000780018c820a0401ffffe004ff00001f00018dc0008082ce2a2219c94c6644d9f056ecc91ba39dfac64c5dd62f26b49e5fa51a28dd880e80808253b8a1bdc3e281fc950d4620e2bae0289df4c3cd34c9e716dc2f0ce022ff223a808072c44e228a92e9c8b7d74686ebb1481eac212d788c8f0a4d67b305210d95d6d22a518deab39110189e0463a677ce47328fdb902ae124bdd85ceaecccce148cac");
        byte[] subjectRaw = Hex.decode("8003008034556d34931e5e5c318300000000001a56170084223860010380012481040301fffc80012581050401ffffff80018d810201000080826804fcef8c89168b7e4ffc0615ef7d64a02cb92456cb6d00baabb71d0adcc690808082b3d838f7d8851b97177a2d314ee6f1c7aadd7273619a4868ad8b0e34443a0e4180806c8e98b60ee6ccbc1d69e0e910c9230cdbbaf013061ca9bf97844bceda4dd0357900bddda50788111db4e833e8850924a2150a5afb5186c1e78908ee5c30af6d");


        ITSCertificate rootCert = loadCertificate(rootCertRaw);
        ITSCertificate issuer = loadCertificate(issuerRaw);

        //
        // Verify issuer against root
        //
        JcaITSContentVerifierProvider provider = new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(rootCert);
        boolean issuerValidAgainstRoot = issuer.isSignatureValid(provider);
        TestCase.assertTrue(issuerValidAgainstRoot);

        ITSCertificate subject = loadCertificate(subjectRaw);

        //
        // Verify subject against issuer
        //
        provider = new JcaITSContentVerifierProvider.Builder().setProvider("BC").build(issuer);
        boolean valid = subject.isSignatureValid(provider);
        TestCase.assertTrue(valid);
    }

}
