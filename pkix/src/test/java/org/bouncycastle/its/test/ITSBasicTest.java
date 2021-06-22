package org.bouncycastle.its.test;

import java.io.ByteArrayInputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSCertificateBuilder;
import org.bouncycastle.its.bc.BcITSContentSigner;
import org.bouncycastle.its.bc.BcITSContentVerifierProvider;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.its.Certificate;
import org.bouncycastle.oer.its.template.IEEE1609dot2;
import org.bouncycastle.util.encoders.Hex;

public class ITSBasicTest
    extends TestCase
{

    public void testSelfSignedCA()
        throws Exception
    {
        byte[] ca = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        ITSCertificate caCert = loadCertificate(ca);

        BcITSContentVerifierProvider provider = new BcITSContentVerifierProvider(caCert);
        boolean valid = caCert.isSignatureValid(provider);
        TestCase.assertTrue(valid);
    }


    public void testBasicVerification()
        throws Exception
    {

        byte[] rootCertRaw = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        byte[] issuerRaw = Hex.decode("80030080c6f1125e19b175ee398300000000001a5617008466a88001018002026f810302013201012080010780012482080301fffc03ff0003800125820a0401ffffff04ff00000080018982060201e002ff1f80018a82060201c002ff3f80018b820e0601000000fff806ff000000000780018c820a0401ffffe004ff00001f00018dc0008082ce2a2219c94c6644d9f056ecc91ba39dfac64c5dd62f26b49e5fa51a28dd880e80808253b8a1bdc3e281fc950d4620e2bae0289df4c3cd34c9e716dc2f0ce022ff223a808072c44e228a92e9c8b7d74686ebb1481eac212d788c8f0a4d67b305210d95d6d22a518deab39110189e0463a677ce47328fdb902ae124bdd85ceaecccce148cac");
        byte[] subjectRaw = Hex.decode("8003008034556d34931e5e5c318300000000001a56170084223860010380012481040301fffc80012581050401ffffff80018d810201000080826804fcef8c89168b7e4ffc0615ef7d64a02cb92456cb6d00baabb71d0adcc690808082b3d838f7d8851b97177a2d314ee6f1c7aadd7273619a4868ad8b0e34443a0e4180806c8e98b60ee6ccbc1d69e0e910c9230cdbbaf013061ca9bf97844bceda4dd0357900bddda50788111db4e833e8850924a2150a5afb5186c1e78908ee5c30af6d");


        ITSCertificate rootCert = loadCertificate(rootCertRaw);
        ITSCertificate issuer = loadCertificate(issuerRaw);

        //
        // Verify issuer against root
        //
        BcITSContentVerifierProvider provider = new BcITSContentVerifierProvider(rootCert);
        boolean issuerValidAgainstRoot = issuer.isSignatureValid(provider);
        TestCase.assertTrue(issuerValidAgainstRoot);

        ITSCertificate subject = loadCertificate(subjectRaw);

        //
        // Verify subject against issuer
        //
        provider = new BcITSContentVerifierProvider(issuer);
        boolean valid = subject.isSignatureValid(provider);
        TestCase.assertTrue(valid);
    }

    public void testBasicGeneration()
        throws Exception
    {

        byte[] issuerRaw = Hex.decode("80030080c6f1125e19b175ee398300000000001a5617008466a88001018002026f810302013201012080010780012482080301fffc03ff0003800125820a0401ffffff04ff00000080018982060201e002ff1f80018a82060201c002ff3f80018b820e0601000000fff806ff000000000780018c820a0401ffffe004ff00001f00018dc0008082ce2a2219c94c6644d9f056ecc91ba39dfac64c5dd62f26b49e5fa51a28dd880e80808253b8a1bdc3e281fc950d4620e2bae0289df4c3cd34c9e716dc2f0ce022ff223a808072c44e228a92e9c8b7d74686ebb1481eac212d788c8f0a4d67b305210d95d6d22a518deab39110189e0463a677ce47328fdb902ae124bdd85ceaecccce148cac");
        byte[] subjectRaw = Hex.decode("8003008034556d34931e5e5c318300000000001a56170084223860010380012481040301fffc80012581050401ffffff80018d810201000080826804fcef8c89168b7e4ffc0615ef7d64a02cb92456cb6d00baabb71d0adcc690808082b3d838f7d8851b97177a2d314ee6f1c7aadd7273619a4868ad8b0e34443a0e4180806c8e98b60ee6ccbc1d69e0e910c9230cdbbaf013061ca9bf97844bceda4dd0357900bddda50788111db4e833e8850924a2150a5afb5186c1e78908ee5c30af6d");

        ITSCertificate issuer = loadCertificate(issuerRaw);
        ITSCertificate subject = loadCertificate(subjectRaw);

        ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

        kpGen.init(new ECKeyGenerationParameters(
            new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, ECNamedCurveTable.getByName("P-256")), new SecureRandom()));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        ITSCertificateBuilder bldr = new ITSCertificateBuilder(subject.toASN1Structure().getCertificateBase().getToBeSignedCertificate());
        BcITSContentSigner signer = new BcITSContentSigner((ECPrivateKeyParameters)kp.getPrivate(), issuer);

        ITSCertificate genCert = bldr.build(signer);

        assertEquals(subject.getIssuer(), genCert.getIssuer());
//   TODO: signature creation is confirmed, but need a way of generating root certificate
//        BcITSContentVerifierProvider provider = new BcITSContentVerifierProvider(issuer);
//        boolean valid = genCert.isSignatureValid(provider);
//        TestCase.assertTrue(valid);
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
        ASN1Object obj = oi.parse(IEEE1609dot2.certificate);
        ITSCertificate certificate = new ITSCertificate(Certificate.getInstance(obj));
        fin.close();
        return certificate;
    }


//    static class HexIn
//        extends FilterInputStream
//    {
//
//        /**
//         * Creates a {@code FilterInputStream}
//         * by assigning the  argument {@code in}
//         * to the field {@code this.in} so as
//         * to remember it for later use.
//         *
//         * @param in the underlying input stream, or {@code null} if
//         *           this instance is to be created without an underlying stream.
//         */
//        protected HexIn(InputStream in)
//        {
//            super(in);
//        }
//
//        @Override
//        public int read()
//            throws IOException
//        {
//            int r = super.read();
//            System.out.println(Hex.toHexString(new byte[]{(byte)(r & 0xFF)}));
//            return r;
//        }
//
//        @Override
//        public int read(byte[] b)
//            throws IOException
//        {
//
//            int i = super.read(b);
//            System.out.println(Hex.toHexString(b));
//            return i;
//        }
//
//        @Override
//        public int read(byte[] b, int off, int len)
//            throws IOException
//        {
//            int i = super.read(b, off, len);
//
//            System.out.println(Hex.toHexString(b, off, i));
//            return i;
//
//        }
//    }

}


