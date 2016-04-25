package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests are taken from RFC 6979 - "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)"
 */
public class DetDSATest
    extends SimpleTest
{

    public static final byte[] SAMPLE = Hex.decode("73616d706c65"); // "sample"
    public static final byte[] TEST = Hex.decode("74657374"); // "test"

    // test vectors from appendix in RFC 6979
    private void testHMacDeterministic()
        throws Exception
    {
        DSAPrivateKeySpec privKeySpec = new DSAPrivateKeySpec(new BigInteger("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7", 16),
            new BigInteger("86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447" +
                           "E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88" +
                           "73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C" +
                           "881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779", 16),
            new BigInteger("996F967F6C8E388D9E28D01E205FBA957A5698B1", 16),
            new BigInteger("07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D" +
                           "89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD" +
                           "87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4" +
                           "17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD", 16));

        KeyFactory keyFact = KeyFactory.getInstance("DSA", "BC");

        PrivateKey privKey = keyFact.generatePrivate(privKeySpec);

        doTestHMACDetDSASample("SHA1withDDSA", privKey, new BigInteger("2E1A0C2562B2912CAAF89186FB0F42001585DA55", 16), new BigInteger("29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5", 16));
        doTestHMACDetDSASample("SHA224withDDSA", privKey, new BigInteger("4BC3B686AEA70145856814A6F1BB53346F02101E", 16), new BigInteger("410697B92295D994D21EDD2F4ADA85566F6F94C1", 16));
        doTestHMACDetDSASample("SHA256withDDSA", privKey, new BigInteger("81F2F5850BE5BC123C43F71A3033E9384611C545", 16), new BigInteger("4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89", 16));
        doTestHMACDetDSASample("SHA384withDDSA", privKey, new BigInteger("07F2108557EE0E3921BC1774F1CA9B410B4CE65A", 16), new BigInteger("54DF70456C86FAC10FAB47C1949AB83F2C6F7595", 16));
        doTestHMACDetDSASample("SHA512withDDSA", privKey, new BigInteger("16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B", 16), new BigInteger("02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C", 16));

        doTestHMACDetDSATest("SHA3-224withDDSA", privKey, new BigInteger("58748b6ca41d25e41f7bfa51fed204a10a1bd1d3", 16), new BigInteger("86de2fdad0bc848dd20ddd9dc6253fc6d7553268", 16));
        doTestHMACDetDSATest("SHA3-256withDDSA", privKey, new BigInteger("98c7a7906ada494285b3ab15cf9188a425f26bd4", 16), new BigInteger("21c5ed876037470d3959fa12f918674a4bf190e9", 16));
        doTestHMACDetDSATest("SHA3-384withDDSA", privKey, new BigInteger("445ec584ec15c14abc67c99886a30a286cc83b33", 16), new BigInteger("21f564d5bb4b175e89a1a6fb2f27cd34c861142d", 16));
        doTestHMACDetDSATest("SHA3-512withDDSA", privKey, new BigInteger("16918083f4c3ff4fc9b327e9e120a30ec39faaf6", 16), new BigInteger("1e9183a1dc7c20dbb596920cd94da3844a087203", 16));
    }

    private void doTestHMACDetDSASample(String algName, PrivateKey privKey, BigInteger r, BigInteger s)
        throws Exception
    {
        doTestHMACDetECDSA(Signature.getInstance(algName, "BC"), SAMPLE, privKey, r, s);
    }

    private void doTestHMACDetDSATest(String algName, PrivateKey privKey, BigInteger r, BigInteger s)
        throws Exception
    {
        doTestHMACDetECDSA(Signature.getInstance(algName, "BC"), TEST, privKey, r, s);
    }

    // test vectors from appendix in RFC 6979
    private void testECHMacDeterministic()
        throws Exception
    {
        X9ECParameters x9ECParameters = NISTNamedCurves.getByName("P-192");
        ECCurve curve = x9ECParameters.getCurve();

        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(new BigInteger("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4", 16),
            new ECParameterSpec(
                new EllipticCurve(new ECFieldFp(((ECCurve.Fp)curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), null),
                new ECPoint(x9ECParameters.getG().getXCoord().toBigInteger(), x9ECParameters.getG().getYCoord().toBigInteger()),
                x9ECParameters.getN(), x9ECParameters.getH().intValue())
            );

        KeyFactory keyFact = KeyFactory.getInstance("ECDSA", "BC");

        PrivateKey privKey = keyFact.generatePrivate(privKeySpec);

        doTestHMACDetECDSASample("SHA1withECDDSA", privKey,   new BigInteger("98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF", 16), new BigInteger("57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64", 16));
        doTestHMACDetECDSASample("SHA224withECDDSA", privKey, new BigInteger("A1F00DAD97AEEC91C95585F36200C65F3C01812AA60378F5", 16), new BigInteger("E07EC1304C7C6C9DEBBE980B9692668F81D4DE7922A0F97A", 16));
        doTestHMACDetECDSASample("SHA256withECDDSA", privKey, new BigInteger("4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55", 16), new BigInteger("CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85", 16));
        doTestHMACDetECDSASample("SHA384withECDDSA", privKey, new BigInteger("DA63BF0B9ABCF948FBB1E9167F136145F7A20426DCC287D5", 16), new BigInteger("C3AA2C960972BD7A2003A57E1C4C77F0578F8AE95E31EC5E", 16));
        doTestHMACDetECDSASample("SHA512withECDDSA", privKey, new BigInteger("4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8", 16), new BigInteger("3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67", 16));

        doTestHMACDetECDSATest("SHA1withECDDSA", privKey,   new BigInteger("0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D", 16), new BigInteger("EB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7", 16));
        doTestHMACDetECDSATest("SHA224withECDDSA", privKey, new BigInteger("6945A1C1D1B2206B8145548F633BB61CEF04891BAF26ED34", 16), new BigInteger("B7FB7FDFC339C0B9BD61A9F5A8EAF9BE58FC5CBA2CB15293", 16));
        doTestHMACDetECDSATest("SHA256withECDDSA", privKey, new BigInteger("3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE", 16), new BigInteger("5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F", 16));
        doTestHMACDetECDSATest("SHA384withECDDSA", privKey, new BigInteger("B234B60B4DB75A733E19280A7A6034BD6B1EE88AF5332367", 16), new BigInteger("7994090B2D59BB782BE57E74A44C9A1C700413F8ABEFE77A", 16));
        doTestHMACDetECDSATest("SHA512withECDDSA", privKey, new BigInteger("FE4F4AE86A58B6507946715934FE2D8FF9D95B6B098FE739", 16), new BigInteger("74CF5605C98FBA0E1EF34D4B5A1577A7DCF59457CAE52290", 16));

        doTestHMACDetECDSATest("SHA3-224withECDDSA", privKey, new BigInteger("abfcb817d04cc223f0d9c02c6db9230a91f955bf4556e0c6", 16), new BigInteger("ec2c29065a50d8ea39533d49472ccf538a5388cb31900e8f", 16));
        doTestHMACDetECDSATest("SHA3-256withECDDSA", privKey, new BigInteger("a2c2d5362d3cea77191edb239bf22a14dcc59d6500a744fc", 16), new BigInteger("6c63f3012353082026be7e2c6f37e6d7811066ddc9b9ee47", 16));
        doTestHMACDetECDSATest("SHA3-384withECDDSA", privKey, new BigInteger("2ff2c37d48cd6691c8adb9d2b1c1af203a1a6b8769c588dd", 16), new BigInteger("79c8171097f845c608dafd218ba096a51e0e4882faf2c08d", 16));
        doTestHMACDetECDSATest("SHA3-512withECDDSA", privKey, new BigInteger("384619b82461f4cc852dfa1e87cd87105e8eb3cfd0fb6461", 16), new BigInteger("d0aac03f72e90942821e3af1f77fd8a6ae82d1ed31b8ed06", 16));
    }

    private void doTestHMACDetECDSASample(String sigAlg, PrivateKey privKey, BigInteger r, BigInteger s)
        throws Exception
    {
        doTestHMACDetECDSA(Signature.getInstance(sigAlg, "BC"), SAMPLE, privKey, r, s);
    }

    private void doTestHMACDetECDSATest(String sigAlg, PrivateKey privKey, BigInteger r, BigInteger s)
        throws Exception
    {
        doTestHMACDetECDSA(Signature.getInstance(sigAlg, "BC"), TEST, privKey, r, s);
    }

    private void doTestHMACDetECDSA(Signature detSigner, byte[] data, PrivateKey privKey, BigInteger r, BigInteger s)
        throws Exception
    {
        detSigner.initSign(privKey);

        detSigner.update(data, 0, data.length);

        byte[] m = detSigner.sign();

        ASN1Sequence seq = ASN1Sequence.getInstance(m);

        if (!r.equals(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue()))
        {
            fail("r value wrong, got " + ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().toString(16) + " expected " + r.toString(16));
        }
        if (!s.equals(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue()))
        {
            fail("s value wrong, got " + ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().toString(16));
        }
    }

    public String getName()
    {
        return "DetDSA";
    }

    public void performTest()
        throws Exception
    {
        testHMacDeterministic();
        testECHMacDeterministic();
    }


    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DetDSATest());
    }
}

