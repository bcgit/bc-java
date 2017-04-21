package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class SM2SignerTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM2Signer";
    }

    private void doSignerTestFp()
        throws Exception
    {
        BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);
        
        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);

        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263", 16));
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        keyPairGenerator.init(keyGenerationParams);
        AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters ecPub = (ECPublicKeyParameters)kp.getPublic();
        ECPrivateKeyParameters ecPriv = (ECPrivateKeyParameters)kp.getPrivate();

        SM2Signer signer = new SM2Signer();

        signer.init(true,
            new ParametersWithID(new ParametersWithRandom(ecPriv,
                    new TestRandomBigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16)),
                Strings.toByteArray("ALICE123@YAHOO.COM")));

        BigInteger[] rs = signer.generateSignature(Strings.toByteArray("message digest"));

        isTrue("r wrong", rs[0].equals(new BigInteger("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1", 16)));
        isTrue("s wrong", rs[1].equals(new BigInteger("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7", 16)));

        signer.init(false, new ParametersWithID(ecPub, Strings.toByteArray("ALICE123@YAHOO.COM")));

        isTrue("verification failed", signer.verifySignature(Strings.toByteArray("message digest"), rs[0], rs[1]));
    }

    private void doSignerTestF2m()
        throws Exception
    {
        BigInteger SM2_ECC_A = new BigInteger("00", 16);
        BigInteger SM2_ECC_B = new BigInteger("E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B", 16);
        BigInteger SM2_ECC_N = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D", 16);
        BigInteger SM2_ECC_GX = new BigInteger("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD", 16);
        BigInteger SM2_ECC_GY = new BigInteger("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E", 16);

        ECCurve curve = new ECCurve.F2m(257, 12, SM2_ECC_A, SM2_ECC_B);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);

        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931", 16));
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        keyPairGenerator.init(keyGenerationParams);
        AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters ecPub = (ECPublicKeyParameters)kp.getPublic();
        ECPrivateKeyParameters ecPriv = (ECPrivateKeyParameters)kp.getPrivate();

        SM2Signer signer = new SM2Signer();

        signer.init(true,
            new ParametersWithID(new ParametersWithRandom(ecPriv,
                    new TestRandomBigInteger("36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6", 16)),
                Strings.toByteArray("ALICE123@YAHOO.COM")));

        BigInteger[] rs = signer.generateSignature(Strings.toByteArray("message digest"));

        isTrue("F2m r wrong", rs[0].equals(new BigInteger("6D3FBA26EAB2A1054F5D198332E335817C8AC453ED26D3391CD4439D825BF25B", 16)));
        isTrue("F2m s wrong", rs[1].equals(new BigInteger("3124C5688D95F0A10252A9BED033BEC84439DA384621B6D6FAD77F94B74A9556", 16)));

        signer.init(false, new ParametersWithID(ecPub, Strings.toByteArray("ALICE123@YAHOO.COM")));

        isTrue("F2m verification failed", signer.verifySignature(Strings.toByteArray("message digest"), rs[0], rs[1]));
    }

    public void performTest()
        throws Exception
    {
        doSignerTestFp();
        doSignerTestF2m();
    }

    public static void main(String[] args)
    {
        runTest(new SM2SignerTest());
    }
}
