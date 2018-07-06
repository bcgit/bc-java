package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class SM2KeyExchangeTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM2KeyExchange";
    }

    private void doKeyExchangeTestFp()
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
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N);

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16));

        keyPairGenerator.init(aKeyGenParams);

        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();

        ECKeyGenerationParameters aeKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16));

        keyPairGenerator.init(aeKeyGenParams);

        AsymmetricCipherKeyPair aeKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aePub = (ECPublicKeyParameters)aeKp.getPublic();
        ECPrivateKeyParameters aePriv = (ECPrivateKeyParameters)aeKp.getPrivate();

        ECKeyGenerationParameters bKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16));

        keyPairGenerator.init(bKeyGenParams);

        AsymmetricCipherKeyPair bKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters bPub = (ECPublicKeyParameters)bKp.getPublic();
        ECPrivateKeyParameters bPriv = (ECPrivateKeyParameters)bKp.getPrivate();

        ECKeyGenerationParameters beKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16));

        keyPairGenerator.init(beKeyGenParams);

        AsymmetricCipherKeyPair beKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters bePub = (ECPublicKeyParameters)beKp.getPublic();
        ECPrivateKeyParameters bePriv = (ECPrivateKeyParameters)beKp.getPrivate();

        SM2KeyExchange exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(true, aPriv, aePriv), Strings.toByteArray("ALICE123@YAHOO.COM")));

        byte[] k1 = exch.calculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParameters(bPub, bePub), Strings.toByteArray("BILL456@YAHOO.COM")));

        isTrue("key 1 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), k1));

        exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(false, bPriv, bePriv), Strings.toByteArray("BILL456@YAHOO.COM")));

        byte[] k2 = exch.calculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParameters(aPub, aePub), Strings.toByteArray("ALICE123@YAHOO.COM")));

        isTrue("key 2 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), k2));

        // with key confirmation
        exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(false, bPriv, bePriv), Strings.toByteArray("BILL456@YAHOO.COM")));

        byte[][] vals2 = exch.calculateKeyWithConfirmation(128, null, new ParametersWithID(new SM2KeyExchangePublicParameters(aPub, aePub), Strings.toByteArray("ALICE123@YAHOO.COM")));

        isTrue("key 2 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), k2));
      
        isTrue("conf a tag 2 wrong", Arrays.areEqual(Hex.decode("284C8F198F141B502E81250F1581C7E9EEB4CA6990F9E02DF388B45471F5BC5C"), vals2[1]));
        isTrue("conf b tag 2 wrong", Arrays.areEqual(Hex.decode("23444DAF8ED7534366CB901C84B3BDBB63504F4065C1116C91A4C00697E6CF7A"), vals2[2]));

        exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(true, aPriv, aePriv), Strings.toByteArray("ALICE123@YAHOO.COM")));

        byte[][] vals1 = exch.calculateKeyWithConfirmation(128, vals2[1], new ParametersWithID(new SM2KeyExchangePublicParameters(bPub, bePub), Strings.toByteArray("BILL456@YAHOO.COM")));

        isTrue("conf key 1 wrong", Arrays.areEqual(Hex.decode("55b0ac62a6b927ba23703832c853ded4"), vals1[0]));
        isTrue("conf tag 1 wrong", Arrays.areEqual(Hex.decode("23444DAF8ED7534366CB901C84B3BDBB63504F4065C1116C91A4C00697E6CF7A"), vals1[1]));
    }

    private void doKeyExchangeTestF2m()
        throws Exception
    {
        BigInteger SM2_ECC_A = new BigInteger("00", 16);
        BigInteger SM2_ECC_B = new BigInteger("E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B", 16);
        BigInteger SM2_ECC_N = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D", 16);
        BigInteger SM2_ECC_H = BigInteger.valueOf(4);
        BigInteger SM2_ECC_GX = new BigInteger("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD", 16);
        BigInteger SM2_ECC_GY = new BigInteger("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E", 16);

        ECCurve curve = new ECCurve.F2m(257, 12, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, SM2_ECC_N, SM2_ECC_H);
        
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        ECKeyGenerationParameters aKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("4813903D254F2C20A94BC5704238496954BB5279F861952EF2C5298E84D2CEAA", 16));

        keyPairGenerator.init(aKeyGenParams);

        AsymmetricCipherKeyPair aKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aPub = (ECPublicKeyParameters)aKp.getPublic();
        ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)aKp.getPrivate();

        ECKeyGenerationParameters aeKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("54A3D6673FF3A6BD6B02EBB164C2A3AF6D4A4906229D9BFCE68CC366A2E64BA4", 16));

        keyPairGenerator.init(aeKeyGenParams);

        AsymmetricCipherKeyPair aeKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters aePub = (ECPublicKeyParameters)aeKp.getPublic();
        ECPrivateKeyParameters aePriv = (ECPrivateKeyParameters)aeKp.getPrivate();

        ECKeyGenerationParameters bKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("08F41BAE0922F47C212803FE681AD52B9BF28A35E1CD0EC273A2CF813E8FD1DC", 16));

        keyPairGenerator.init(bKeyGenParams);

        AsymmetricCipherKeyPair bKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters bPub = (ECPublicKeyParameters)bKp.getPublic();
        ECPrivateKeyParameters bPriv = (ECPrivateKeyParameters)bKp.getPrivate();

        ECKeyGenerationParameters beKeyGenParams = new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("1F21933387BEF781D0A8F7FD708C5AE0A56EE3F423DBC2FE5BDF6F068C53F7AD", 16));

        keyPairGenerator.init(beKeyGenParams);

        AsymmetricCipherKeyPair beKp = keyPairGenerator.generateKeyPair();

        ECPublicKeyParameters bePub = (ECPublicKeyParameters)beKp.getPublic();
        ECPrivateKeyParameters bePriv = (ECPrivateKeyParameters)beKp.getPrivate();

        SM2KeyExchange exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(true, aPriv, aePriv), Strings.toByteArray("ALICE123@YAHOO.COM")));

        byte[] k1 = exch.calculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParameters(bPub, bePub), Strings.toByteArray("BILL456@YAHOO.COM")));

        // there appears to be typo for ZA in the draft
        //isTrue("F2m key 1 wrong", Arrays.areEqual(Hex.decode("4E587E5C66634F22D973A7D98BF8BE23"), k1));
        isTrue("F2m key 1 wrong", Arrays.areEqual(Hex.decode("8c2b03289aa7126555dc660cfc29fd74"), k1));

        exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(false, bPriv, bePriv), Strings.toByteArray("BILL456@YAHOO.COM")));

        byte[] k2 = exch.calculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParameters(aPub, aePub), Strings.toByteArray("ALICE123@YAHOO.COM")));

        //isTrue("F2m key 2 wrong", Arrays.areEqual(Hex.decode("4E587E5C66634F22D973A7D98BF8BE23"), k2));
        isTrue("F2m key 2 wrong", Arrays.areEqual(Hex.decode("8c2b03289aa7126555dc660cfc29fd74"), k2));

        // with key confirmation
        exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(false, bPriv, bePriv), Strings.toByteArray("BILL456@YAHOO.COM")));

        byte[][] vals2 = exch.calculateKeyWithConfirmation(128, null, new ParametersWithID(new SM2KeyExchangePublicParameters(aPub, aePub), Strings.toByteArray("ALICE123@YAHOO.COM")));

        isTrue("key 2 wrong", Arrays.areEqual(Hex.decode("8c2b03289aa7126555dc660cfc29fd74"), k2));

        isTrue("conf a tag 2 wrong", Arrays.areEqual(Hex.decode("d8294c4c0f0ac180feac95e8a0d786638c9e915b9a684b2348809af03a0de2a5"), vals2[1]));
        isTrue("conf b tag 2 wrong", Arrays.areEqual(Hex.decode("52089e706911b58fd5e7c7b2ab5cf32bb61e481ef1e114a1e33d99eec84b5a4f"), vals2[2]));

        exch = new SM2KeyExchange();

        exch.init(new ParametersWithID(new SM2KeyExchangePrivateParameters(true, aPriv, aePriv), Strings.toByteArray("ALICE123@YAHOO.COM")));

        byte[][] vals1 = exch.calculateKeyWithConfirmation(128, vals2[1], new ParametersWithID(new SM2KeyExchangePublicParameters(bPub, bePub), Strings.toByteArray("BILL456@YAHOO.COM")));

        isTrue("conf key 1 wrong", Arrays.areEqual(Hex.decode("8c2b03289aa7126555dc660cfc29fd74"), vals1[0]));
        isTrue("conf tag 1 wrong", Arrays.areEqual(Hex.decode("52089e706911b58fd5e7c7b2ab5cf32bb61e481ef1e114a1e33d99eec84b5a4f"), vals1[1]));
    }

    public void performTest()
        throws Exception
    {
        doKeyExchangeTestFp();
        doKeyExchangeTestF2m();
    }

    public static void main(String[] args)
    {
        runTest(new SM2KeyExchangeTest());
    }
}
