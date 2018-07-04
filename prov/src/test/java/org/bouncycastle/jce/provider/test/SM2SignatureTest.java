package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class SM2SignatureTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM2";
    }

    private void doSignerTestFp()
        throws Exception
    {
        BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        BigInteger SM2_ECC_H = ECConstants.ONE;
        BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECParameterSpec(curve, g, SM2_ECC_N), new TestRandomBigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", 16));

        KeyPair kp = kpGen.generateKeyPair();

        Signature signer = Signature.getInstance("SM3withSM2", "BC");

        signer.setParameter(new SM2ParameterSpec(Strings.toByteArray("ALICE123@YAHOO.COM")));

        // repetition test
        final int times = 2;
        String random = "";
        for (int i = 0; i < times; i++) {
            random += "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
        }
        signer.initSign(kp.getPrivate(),
                    new TestRandomBigInteger(random, 16));

        byte[] msg = Strings.toByteArray("message digest");

        Signature verifier = Signature.getInstance("SM3withSM2", "BC");

        verifier.setParameter(new SM2ParameterSpec(Strings.toByteArray("ALICE123@YAHOO.COM")));

        verifier.initVerify(kp.getPublic());

        for (int i = 0; i < times; i++) {
            signer.update(msg, 0, msg.length);

            byte[] sig = signer.sign();

            BigInteger[] rs = decode(sig);

            isTrue("r wrong", rs[0].equals(new BigInteger("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1", 16)));
            isTrue("s wrong", rs[1].equals(new BigInteger("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7", 16)));

            verifier.update(msg, 0, msg.length);

            isTrue("verification failed i=" + i, verifier.verify(sig));
        }
    }

    private static BigInteger[] decode(byte[] sig)
    {
        ASN1Sequence s = ASN1Sequence.getInstance(sig);

        return new BigInteger[] { ASN1Integer.getInstance(s.getObjectAt(0)).getValue(),
            ASN1Integer.getInstance(s.getObjectAt(1)).getValue() };
    }

    public void performTest()
        throws Exception
    {
        doSignerTestFp();
    }
    
    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SM2SignatureTest());
    }
}
