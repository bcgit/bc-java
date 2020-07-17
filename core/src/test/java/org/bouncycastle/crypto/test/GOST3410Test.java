package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.GOST3410KeyPairGenerator;
import org.bouncycastle.crypto.generators.GOST3410ParametersGenerator;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.GOST3410KeyGenerationParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.GOST3410Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.NumberParsing;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestRandomData;
import org.bouncycastle.util.test.TestResult;

public class GOST3410Test
    implements Test
{
    private static ECNamedDomainParameters getECNamedDomainParameters(ASN1ObjectIdentifier oid)
    {
        X9ECParameters x9 = ECGOST3410NamedCurves.getByOIDX9(oid);
        return new ECNamedDomainParameters(oid, x9);
    }

    byte[] hashmessage = Hex.decode("3042453136414534424341374533364339313734453431443642453241453435");

    private byte[] zeroTwo(int length)
    {
        byte[] data = new byte[length];
        data[data.length - 1] = 0x02;
        return data;
    }


    Test tests[] =
        {
            new GOST3410EncodingDecoding(),
            new GOST3410_TEST1_512(),
            new GOST3410_TEST2_512(),
            new GOST3410_TEST1_1024(),
            new GOST3410_TEST2_1024(),
            new GOST3410_AParam(),
            new GOST3410_BParam(),
            new GOST3410_CParam(),
            new GOST3410_DParam(),
            new GOST3410_AExParam(),
            new GOST3410_BExParam(),
            new GOST3410_CExParam()
        };

    public static void main(
        String[] args)
    {
        GOST3410Test test = new GOST3410Test();
        TestResult result = test.perform();

        System.out.println(result);
    }

    public TestResult perform()
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult result = tests[i].perform();

            if (!result.isSuccessful())
            {
                return result;
            }
        }

        return new SimpleTestResult(true, "GOST3410: Okay");
    }

    private class GOST3410EncodingDecoding
        implements Test
    {

        public String getName()
        {
            return "GOST3410ParameterEncodeDecode";
        }


        private SimpleTestResult encodeRecodePrivateKeyGost2006()
        {
            try
            {
                ASN1ObjectIdentifier oid = ECGOST3410NamedCurves.getOID("GostR3410-2001-CryptoPro-A");
                ECNamedDomainParameters ecp = getECNamedDomainParameters(oid);
                ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, CryptoProObjectIdentifiers.gostR3411);
                ECKeyGenerationParameters params = new ECKeyGenerationParameters(gostParams, new SecureRandom());
                ECKeyPairGenerator engine = new ECKeyPairGenerator();
                engine.init(params);
                AsymmetricCipherKeyPair pair = engine.generateKeyPair();

                ECPrivateKeyParameters generatedKeyParameters = (ECPrivateKeyParameters)pair.getPrivate();
                ECPrivateKeyParameters keyParameters = generatedKeyParameters;


                //
                // Continuously encode/decode the key and check for loss of information.
                //


                for (int t = 0; t < 3; t++)
                {
                    PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParameters);
                    keyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.createKey(info);

                    { // Specifically cast and test gost parameters.
                        ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.getParameters();
                        ECGOST3410Parameters rParam = (ECGOST3410Parameters)keyParameters.getParameters();

                        boolean ok = safeEquals(gParam.getDigestParamSet(), rParam.getDigestParamSet()) &&
                            safeEquals(gParam.getEncryptionParamSet(), rParam.getEncryptionParamSet()) &&
                            safeEquals(gParam.getPublicKeyParamSet(), rParam.getPublicKeyParamSet());

                        if (!ok)
                        {
                            return new SimpleTestResult(false, "GOST parameters does not match");
                        }

                    }

                    if (keyParameters.isPrivate() != generatedKeyParameters.isPrivate())
                    {
                        return new SimpleTestResult(false, "isPrivate does not match");
                    }

                    if (!keyParameters.getD().equals(generatedKeyParameters.getD()))
                    {
                        return new SimpleTestResult(false, "D does not match");
                    }

                    if (!((ECGOST3410Parameters)keyParameters.getParameters()).getName().equals(
                        ((ECGOST3410Parameters)generatedKeyParameters.getParameters()).getName()))
                    {
                        return new SimpleTestResult(false, "Name does not match");
                    }

                    if (!keyParameters.getParameters().getCurve().equals(generatedKeyParameters.getParameters().getCurve()))
                    {
                        return new SimpleTestResult(false, "Curve does not match");
                    }

                    if (!Arrays.areEqual(
                        keyParameters.getParameters().getG().getEncoded(true),
                        generatedKeyParameters.getParameters().getG().getEncoded(true)))
                    {
                        return new SimpleTestResult(false, "G does not match");
                    }

                    if (!keyParameters.getParameters().getH().equals(generatedKeyParameters.getParameters().getH()))
                    {
                        return new SimpleTestResult(false, "H does not match");
                    }

                    if (!keyParameters.getParameters().getHInv().equals(generatedKeyParameters.getParameters().getHInv()))
                    {
                        return new SimpleTestResult(false, "Hinv does not match");
                    }

                    if (!keyParameters.getParameters().getN().equals(generatedKeyParameters.getParameters().getN()))
                    {
                        return new SimpleTestResult(false, "N does not match");
                    }

                    if (!Arrays.areEqual(keyParameters.getParameters().getSeed(), generatedKeyParameters.getParameters().getSeed()))
                    {
                        return new SimpleTestResult(false, "Seed does not match");
                    }
                }


            }
            catch (Exception ex)
            {
                return new SimpleTestResult(false, ex.getMessage(), ex);
            }

            return new SimpleTestResult(true, null);
        }


        public SimpleTestResult encodeRecodePublicKeyGost2006()
        {
            ASN1ObjectIdentifier oid = ECGOST3410NamedCurves.getOID("GostR3410-2001-CryptoPro-A");
            ECNamedDomainParameters ecp = getECNamedDomainParameters(oid);
            ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, CryptoProObjectIdentifiers.gostR3411);
            ECKeyGenerationParameters params = new ECKeyGenerationParameters(gostParams, new SecureRandom());
            ECKeyPairGenerator engine = new ECKeyPairGenerator();
            engine.init(params);
            AsymmetricCipherKeyPair pair = engine.generateKeyPair();

            ECPublicKeyParameters generatedKeyParameters = (ECPublicKeyParameters)pair.getPublic();
            ECPublicKeyParameters keyParameters = generatedKeyParameters;

            try
            {
                for (int t = 0; t < 3; t++)
                {

                    SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParameters);
                    keyParameters = (ECPublicKeyParameters)PublicKeyFactory.createKey(info);

                    { // Specifically cast and test gost parameters.
                        ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.getParameters();
                        ECGOST3410Parameters rParam = (ECGOST3410Parameters)keyParameters.getParameters();


                        boolean ok = safeEquals(gParam.getDigestParamSet(), rParam.getDigestParamSet()) &&
                            safeEquals(gParam.getEncryptionParamSet(), rParam.getEncryptionParamSet()) &&
                            safeEquals(gParam.getPublicKeyParamSet(), rParam.getPublicKeyParamSet());

                        if (!ok)
                        {
                            return new SimpleTestResult(false, "GOST parameters does not match");
                        }

                    }

                    if (!((ECGOST3410Parameters)keyParameters.getParameters()).getName().equals(
                        ((ECGOST3410Parameters)generatedKeyParameters.getParameters()).getName()))
                    {
                        return new SimpleTestResult(false, "Name does not match");
                    }


                    if (keyParameters.isPrivate() != generatedKeyParameters.isPrivate())
                    {
                        return new SimpleTestResult(false, "isPrivate does not match");
                    }

                    if (!Arrays.areEqual(keyParameters.getQ().getEncoded(true), generatedKeyParameters.getQ().getEncoded(true)))
                    {
                        return new SimpleTestResult(false, "Q does not match");
                    }

                    if (!keyParameters.getParameters().getCurve().equals(generatedKeyParameters.getParameters().getCurve()))
                    {
                        return new SimpleTestResult(false, "Curve does not match");
                    }

                    if (!Arrays.areEqual(
                        keyParameters.getParameters().getG().getEncoded(true),
                        generatedKeyParameters.getParameters().getG().getEncoded(true)))
                    {
                        return new SimpleTestResult(false, "G does not match");
                    }

                    if (!keyParameters.getParameters().getH().equals(generatedKeyParameters.getParameters().getH()))
                    {
                        return new SimpleTestResult(false, "H does not match");
                    }

                    if (!keyParameters.getParameters().getHInv().equals(generatedKeyParameters.getParameters().getHInv()))
                    {
                        return new SimpleTestResult(false, "Hinv does not match");
                    }

                    if (!keyParameters.getParameters().getN().equals(generatedKeyParameters.getParameters().getN()))
                    {
                        return new SimpleTestResult(false, "N does not match");
                    }

                    if (!Arrays.areEqual(keyParameters.getParameters().getSeed(), generatedKeyParameters.getParameters().getSeed()))
                    {
                        return new SimpleTestResult(false, "Seed does not match");
                    }
                }
                return new SimpleTestResult(true, null);
            }
            catch (Exception ex)
            {
                return new SimpleTestResult(false, ex.getMessage(), ex);
            }


        }


        public SimpleTestResult encodeRecodePublicKey()
        {

            ASN1ObjectIdentifier oid = ECGOST3410NamedCurves.getOID("Tc26-Gost-3410-12-512-paramSetA");
            ECNamedDomainParameters ecp = getECNamedDomainParameters(oid);
            ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
            ECKeyGenerationParameters params = new ECKeyGenerationParameters(gostParams, new SecureRandom());
            ECKeyPairGenerator engine = new ECKeyPairGenerator();
            engine.init(params);
            AsymmetricCipherKeyPair pair = engine.generateKeyPair();

            ECPublicKeyParameters generatedKeyParameters = (ECPublicKeyParameters)pair.getPublic();
            ECPublicKeyParameters keyParameters = generatedKeyParameters;


            //
            // Continuously encode/decode the key and check for loss of information.
            //
            try
            {
                for (int t = 0; t < 3; t++)
                {

                    SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyParameters);
                    keyParameters = (ECPublicKeyParameters)PublicKeyFactory.createKey(info);

                    { // Specifically cast and test gost parameters.
                        ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.getParameters();
                        ECGOST3410Parameters rParam = (ECGOST3410Parameters)keyParameters.getParameters();


                        boolean ok = safeEquals(gParam.getDigestParamSet(), rParam.getDigestParamSet()) &&
                            safeEquals(gParam.getEncryptionParamSet(), rParam.getEncryptionParamSet()) &&
                            safeEquals(gParam.getPublicKeyParamSet(), rParam.getPublicKeyParamSet());

                        if (!ok)
                        {
                            return new SimpleTestResult(false, "GOST parameters does not match");
                        }

                    }

                    if (!((ECGOST3410Parameters)keyParameters.getParameters()).getName().equals(
                        ((ECGOST3410Parameters)generatedKeyParameters.getParameters()).getName()))
                    {
                        return new SimpleTestResult(false, "Name does not match");
                    }


                    if (keyParameters.isPrivate() != generatedKeyParameters.isPrivate())
                    {
                        return new SimpleTestResult(false, "isPrivate does not match");
                    }

                    if (!Arrays.areEqual(keyParameters.getQ().getEncoded(true), generatedKeyParameters.getQ().getEncoded(true)))
                    {
                        return new SimpleTestResult(false, "Q does not match");
                    }

                    if (!keyParameters.getParameters().getCurve().equals(generatedKeyParameters.getParameters().getCurve()))
                    {
                        return new SimpleTestResult(false, "Curve does not match");
                    }

                    if (!Arrays.areEqual(
                        keyParameters.getParameters().getG().getEncoded(true),
                        generatedKeyParameters.getParameters().getG().getEncoded(true)))
                    {
                        return new SimpleTestResult(false, "G does not match");
                    }

                    if (!keyParameters.getParameters().getH().equals(generatedKeyParameters.getParameters().getH()))
                    {
                        return new SimpleTestResult(false, "H does not match");
                    }

                    if (!keyParameters.getParameters().getHInv().equals(generatedKeyParameters.getParameters().getHInv()))
                    {
                        return new SimpleTestResult(false, "Hinv does not match");
                    }

                    if (!keyParameters.getParameters().getN().equals(generatedKeyParameters.getParameters().getN()))
                    {
                        return new SimpleTestResult(false, "N does not match");
                    }

                    if (!Arrays.areEqual(keyParameters.getParameters().getSeed(), generatedKeyParameters.getParameters().getSeed()))
                    {
                        return new SimpleTestResult(false, "Seed does not match");
                    }
                }
                return new SimpleTestResult(true, null);
            }
            catch (Exception ex)
            {
                return new SimpleTestResult(false, ex.getMessage(), ex);
            }


        }


        private SimpleTestResult encodeRecodePrivateKey()
        {
            try
            {
                ASN1ObjectIdentifier oid = ECGOST3410NamedCurves.getOID("Tc26-Gost-3410-12-512-paramSetA");
                ECNamedDomainParameters ecp = getECNamedDomainParameters(oid);
                ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
                ECKeyGenerationParameters params = new ECKeyGenerationParameters(gostParams, new SecureRandom());
                ECKeyPairGenerator engine = new ECKeyPairGenerator();
                engine.init(params);
                AsymmetricCipherKeyPair pair = engine.generateKeyPair();

                ECPrivateKeyParameters generatedKeyParameters = (ECPrivateKeyParameters)pair.getPrivate();
                ECPrivateKeyParameters keyParameters = generatedKeyParameters;


                //
                // Continuously encode/decode the key and check for loss of information.
                //


                for (int t = 0; t < 3; t++)
                {
                    PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(keyParameters);
                    keyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.createKey(info);

                    { // Specifically cast and test gost parameters.
                        ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.getParameters();
                        ECGOST3410Parameters rParam = (ECGOST3410Parameters)keyParameters.getParameters();

                        boolean ok = safeEquals(gParam.getDigestParamSet(), rParam.getDigestParamSet()) &&
                            safeEquals(gParam.getEncryptionParamSet(), rParam.getEncryptionParamSet()) &&
                            safeEquals(gParam.getPublicKeyParamSet(), rParam.getPublicKeyParamSet());

                        if (!ok)
                        {
                            return new SimpleTestResult(false, "GOST parameters does not match");
                        }

                    }

                    if (keyParameters.isPrivate() != generatedKeyParameters.isPrivate())
                    {
                        return new SimpleTestResult(false, "isPrivate does not match");
                    }

                    if (!keyParameters.getD().equals(generatedKeyParameters.getD()))
                    {
                        return new SimpleTestResult(false, "D does not match");
                    }

                    if (!((ECGOST3410Parameters)keyParameters.getParameters()).getName().equals(
                        ((ECGOST3410Parameters)generatedKeyParameters.getParameters()).getName()))
                    {
                        return new SimpleTestResult(false, "Name does not match");
                    }

                    if (!keyParameters.getParameters().getCurve().equals(generatedKeyParameters.getParameters().getCurve()))
                    {
                        return new SimpleTestResult(false, "Curve does not match");
                    }

                    if (!Arrays.areEqual(
                        keyParameters.getParameters().getG().getEncoded(true),
                        generatedKeyParameters.getParameters().getG().getEncoded(true)))
                    {
                        return new SimpleTestResult(false, "G does not match");
                    }

                    if (!keyParameters.getParameters().getH().equals(generatedKeyParameters.getParameters().getH()))
                    {
                        return new SimpleTestResult(false, "H does not match");
                    }

                    if (!keyParameters.getParameters().getHInv().equals(generatedKeyParameters.getParameters().getHInv()))
                    {
                        return new SimpleTestResult(false, "Hinv does not match");
                    }

                    if (!keyParameters.getParameters().getN().equals(generatedKeyParameters.getParameters().getN()))
                    {
                        return new SimpleTestResult(false, "N does not match");
                    }

                    if (!Arrays.areEqual(keyParameters.getParameters().getSeed(), generatedKeyParameters.getParameters().getSeed()))
                    {
                        return new SimpleTestResult(false, "Seed does not match");
                    }
                }


            }
            catch (Exception ex)
            {
                return new SimpleTestResult(false, ex.getMessage(), ex);
            }

            return new SimpleTestResult(true, null);
        }


        private SimpleTestResult decodeJCEPublic()
        {
            byte[] pub256 = Hex.decode("3068302106082a85030701010101301506092a850307010201010106082a850307010102020343000440292335c87d892510c35a033819a13e2b0dc606d911676af2bad8872d74a4b7bae6c729e98ace04c3dee626343f794731e1489edb7bc26f1c8c56e1448c96501a");

            try
            {
                ECPublicKeyParameters pkInfo = (ECPublicKeyParameters)PublicKeyFactory.createKey(pub256);

                if (pkInfo.isPrivate())
                {
                    return new SimpleTestResult(false, "isPrivate should be false");
                }

                if (
                    !Arrays.areEqual(
                        pkInfo.getQ().getEncoded(true),
                        Hex.decode("02bab7a4742d87d8baf26a6711d906c60d2b3ea11938035ac31025897dc8352329")))
                {
                    return new SimpleTestResult(false, "Q does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getPublicKeyParamSet().toString().equals("1.2.643.7.1.2.1.1.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getDigestParamSet().toString().equals("1.2.643.7.1.1.2.2"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.getParameters()).getEncryptionParamSet() != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }


                byte[] pub512 = Hex.decode("3081aa302106082a85030701010102301506092a850307010201020106082a850307010102030381840004818043ccc22692ee8a1870c7c9de0566d7e3a494cf0e3c80f9e8852a3d1ec10d2a829d357253e0864aee2eaacd5e2d327578dee771f62f24decfd6358e06199efe540e7912db43c4c80fe0fd31f7f67a862f9d44fd0075cfee6e3d638c7520063d26311ef962547e8129fb8c5b194e129370cd30313884b4a60872254a10772fe595");

                pkInfo = (ECPublicKeyParameters)PublicKeyFactory.createKey(pub512);

                if (pkInfo.isPrivate())
                {
                    return new SimpleTestResult(false, "isPrivate should be true");
                }

                if (
                    !Arrays.areEqual(
                        pkInfo.getQ().getEncoded(true),
                        Hex.decode("0254fe9e19068e35d6cfde242ff671e7de7875322d5ecdaa2eee4a86e05372359d822a0dc11e3d2a85e8f9803c0ecf94a4e3d76605dec9c770188aee9226c2cc43")))
                {
                    return new SimpleTestResult(false, "Q does not match");
                }


                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getPublicKeyParamSet().toString().equals("1.2.643.7.1.2.1.2.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getDigestParamSet().toString().equals("1.2.643.7.1.1.2.3"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.getParameters()).getEncryptionParamSet() != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }

            }
            catch (Exception ex)
            {
                return new SimpleTestResult(false, ex.getMessage(), ex);
            }

            return new SimpleTestResult(true, null);
        }


        private SimpleTestResult decodeJCEPrivate()
        {
            byte[] priv256 = Hex.decode("304a020100302106082a85030701010101301506092a850307010201010106082a8503070101020204220420fe75ba328d5439ed4859e6dc7e6ca2e9aab0818f094eddeb0d57d1c16a90762b");

            try
            {
                ECPrivateKeyParameters pkInfo = (ECPrivateKeyParameters)PrivateKeyFactory.createKey(priv256);

                if (!pkInfo.isPrivate())
                {
                    return new SimpleTestResult(false, "isPrivate should be true");
                }

                if (
                    !Arrays.areEqual(
                        Hex.decode("2b76906ac1d1570debdd4e098f81b0aae9a26c7edce65948ed39548d32ba75fe"),
                        pkInfo.getD().toByteArray()))
                {
                    return new SimpleTestResult(false, "D does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getPublicKeyParamSet().toString().equals("1.2.643.7.1.2.1.1.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getDigestParamSet().toString().equals("1.2.643.7.1.1.2.2"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.getParameters()).getEncryptionParamSet() != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }


                byte[] priv512 = Hex.decode("306a020100302106082a85030701010102301506092a850307010201020106082a85030701010203044204402fc35576152f6e873236608b592b4b98d0793bf5184f8dc4a99512be703716991a96061ef46aceeae5319b5c69e6fcbfa7e339207878597ce50f9b7cbf857ff1");

                pkInfo = (ECPrivateKeyParameters)PrivateKeyFactory.createKey(priv512);

                if (!pkInfo.isPrivate())
                {
                    return new SimpleTestResult(false, "isPrivate should be true");
                }

                if (
                    !Arrays.areEqual(
                        Hex.decode("00f17f85bf7c9b0fe57c5978782039e3a7bffce6695c9b31e5eace6af41e06961a99163770be1295a9c48d4f18f53b79d0984b2b598b603632876e2f157655c32f"),
                        pkInfo.getD().toByteArray()))
                {
                    return new SimpleTestResult(false, "D does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getPublicKeyParamSet().toString().equals("1.2.643.7.1.2.1.2.1"))
                {
                    return new SimpleTestResult(false, "PublicKeyParamSet does not match");
                }

                if (!((ECGOST3410Parameters)pkInfo.getParameters()).getDigestParamSet().toString().equals("1.2.643.7.1.1.2.3"))
                {
                    return new SimpleTestResult(false, "DigestParamSet does not match");
                }

                if (((ECGOST3410Parameters)pkInfo.getParameters()).getEncryptionParamSet() != null)
                {
                    return new SimpleTestResult(false, "EncryptionParamSet is not null");
                }

            }
            catch (Exception ex)
            {
                return new SimpleTestResult(false, ex.getMessage(), ex);
            }

            return new SimpleTestResult(true, null);
        }


        private SimpleTestResult encodeDecodePrivateLW(String oidStr, ASN1ObjectIdentifier digest)
        {
            try
            {
                ASN1ObjectIdentifier oid = ECGOST3410NamedCurves.getOID(oidStr);
                ECNamedDomainParameters ecp = getECNamedDomainParameters(oid);
                ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, digest);
                ECKeyGenerationParameters params = new ECKeyGenerationParameters(gostParams, new SecureRandom());
                ECKeyPairGenerator engine = new ECKeyPairGenerator();
                engine.init(params);
                AsymmetricCipherKeyPair pair = engine.generateKeyPair();

                ECPrivateKeyParameters generatedKeyParameters = (ECPrivateKeyParameters)pair.getPrivate();

                PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(generatedKeyParameters);

                ECPrivateKeyParameters recoveredKeyParameters = (ECPrivateKeyParameters)PrivateKeyFactory.createKey(info);

                { // Specifically cast and test gost parameters.
                    ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.getParameters();
                    ECGOST3410Parameters rParam = (ECGOST3410Parameters)recoveredKeyParameters.getParameters();

                    boolean ok = safeEquals(gParam.getDigestParamSet(), rParam.getDigestParamSet()) &&
                        safeEquals(gParam.getEncryptionParamSet(), rParam.getEncryptionParamSet()) &&
                        safeEquals(gParam.getPublicKeyParamSet(), rParam.getPublicKeyParamSet());

                    if (!ok)
                    {
                        return new SimpleTestResult(false, "GOST parameters does not match");
                    }

                }


                if (recoveredKeyParameters.isPrivate() != generatedKeyParameters.isPrivate())
                {
                    return new SimpleTestResult(false, "isPrivate does not match");
                }

                if (!((ECGOST3410Parameters)recoveredKeyParameters.getParameters()).getName().equals(
                    ((ECGOST3410Parameters)generatedKeyParameters.getParameters()).getName()))
                {
                    return new SimpleTestResult(false, "Name does not match");
                }


                if (!recoveredKeyParameters.getD().equals(generatedKeyParameters.getD()))
                {
                    return new SimpleTestResult(false, "D does not match");
                }

                if (!recoveredKeyParameters.getParameters().getCurve().equals(generatedKeyParameters.getParameters().getCurve()))
                {
                    return new SimpleTestResult(false, "Curve does not match");
                }

                if (!Arrays.areEqual(
                    recoveredKeyParameters.getParameters().getG().getEncoded(true),
                    generatedKeyParameters.getParameters().getG().getEncoded(true)))
                {
                    return new SimpleTestResult(false, "G does not match");
                }

                if (!recoveredKeyParameters.getParameters().getH().equals(generatedKeyParameters.getParameters().getH()))
                {
                    return new SimpleTestResult(false, "H does not match");
                }

                if (!recoveredKeyParameters.getParameters().getHInv().equals(generatedKeyParameters.getParameters().getHInv()))
                {
                    return new SimpleTestResult(false, "Hinv does not match");
                }

                if (!recoveredKeyParameters.getParameters().getN().equals(generatedKeyParameters.getParameters().getN()))
                {
                    return new SimpleTestResult(false, "N does not match");
                }

                if (!Arrays.areEqual(recoveredKeyParameters.getParameters().getSeed(), generatedKeyParameters.getParameters().getSeed()))
                {
                    return new SimpleTestResult(false, "Seed does not match");
                }

                return new SimpleTestResult(true, null);
            }
            catch (Exception t)
            {
                // Any exception is bad.
                return new SimpleTestResult(false, t.getMessage(), t);
            }
        }


        private SimpleTestResult encodeDecodePublicLW(String oidStr, ASN1ObjectIdentifier digest)
        {
            try
            {
                ASN1ObjectIdentifier oid = ECGOST3410NamedCurves.getOID(oidStr);
                ECNamedDomainParameters ecp = getECNamedDomainParameters(oid);
                ECGOST3410Parameters gostParams = new ECGOST3410Parameters(ecp, oid, digest);
                ECKeyGenerationParameters params = new ECKeyGenerationParameters(gostParams, new SecureRandom());
                ECKeyPairGenerator engine = new ECKeyPairGenerator();
                engine.init(params);
                AsymmetricCipherKeyPair pair = engine.generateKeyPair();

                ECPublicKeyParameters generatedKeyParameters = (ECPublicKeyParameters)pair.getPublic();

                SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(generatedKeyParameters);

                ECPublicKeyParameters recoveredKeyParameters = (ECPublicKeyParameters)PublicKeyFactory.createKey(info);

                { // Specifically cast and test gost parameters.
                    ECGOST3410Parameters gParam = (ECGOST3410Parameters)generatedKeyParameters.getParameters();
                    ECGOST3410Parameters rParam = (ECGOST3410Parameters)recoveredKeyParameters.getParameters();


                    boolean ok = safeEquals(gParam.getDigestParamSet(), rParam.getDigestParamSet()) &&
                        safeEquals(gParam.getEncryptionParamSet(), rParam.getEncryptionParamSet()) &&
                        safeEquals(gParam.getPublicKeyParamSet(), rParam.getPublicKeyParamSet());

                    if (!ok)
                    {
                        return new SimpleTestResult(false, "GOST parameters does not match");
                    }

                }

                if (!((ECGOST3410Parameters)recoveredKeyParameters.getParameters()).getName().equals(
                    ((ECGOST3410Parameters)generatedKeyParameters.getParameters()).getName()))
                {
                    return new SimpleTestResult(false, "Name does not match");
                }


                if (recoveredKeyParameters.isPrivate() != generatedKeyParameters.isPrivate())
                {
                    return new SimpleTestResult(false, "isPrivate does not match");
                }

                if (!Arrays.areEqual(recoveredKeyParameters.getQ().getEncoded(true), generatedKeyParameters.getQ().getEncoded(true)))
                {
                    return new SimpleTestResult(false, "Q does not match");
                }

                if (!recoveredKeyParameters.getParameters().getCurve().equals(generatedKeyParameters.getParameters().getCurve()))
                {
                    return new SimpleTestResult(false, "Curve does not match");
                }

                if (!Arrays.areEqual(
                    recoveredKeyParameters.getParameters().getG().getEncoded(true),
                    generatedKeyParameters.getParameters().getG().getEncoded(true)))
                {
                    return new SimpleTestResult(false, "G does not match");
                }

                if (!recoveredKeyParameters.getParameters().getH().equals(generatedKeyParameters.getParameters().getH()))
                {
                    return new SimpleTestResult(false, "H does not match");
                }

                if (!recoveredKeyParameters.getParameters().getHInv().equals(generatedKeyParameters.getParameters().getHInv()))
                {
                    return new SimpleTestResult(false, "Hinv does not match");
                }

                if (!recoveredKeyParameters.getParameters().getN().equals(generatedKeyParameters.getParameters().getN()))
                {
                    return new SimpleTestResult(false, "N does not match");
                }

                if (!Arrays.areEqual(recoveredKeyParameters.getParameters().getSeed(), generatedKeyParameters.getParameters().getSeed()))
                {
                    return new SimpleTestResult(false, "Seed does not match");
                }

                return new SimpleTestResult(true, null);
            }
            catch (Exception t)
            {
                // Any exception is bad.
                return new SimpleTestResult(false, t.getMessage(), t);
            }
        }


        private boolean safeEquals(Object left, Object right)
        {
            if (left == null || right == null)
            {
                return left == null && right == null;
            }

            return left.equals(right);
        }

        public TestResult perform()
        {

            SimpleTestResult str = encodeDecodePublicLW("Tc26-Gost-3410-12-512-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
            if (!str.isSuccessful())
            {
                return str;
            }

            str = encodeDecodePrivateLW("Tc26-Gost-3410-12-512-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
            if (!str.isSuccessful())
            {
                return str;
            }


            str = encodeDecodePublicLW("Tc26-Gost-3410-12-256-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            if (!str.isSuccessful())
            {
                return str;
            }

            str = encodeDecodePrivateLW("Tc26-Gost-3410-12-256-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            if (!str.isSuccessful())
            {
                return str;
            }

            str = decodeJCEPrivate();
            if (!str.isSuccessful())
            {
                return str;
            }

            str = decodeJCEPublic();
            if (!str.isSuccessful())
            {
                return str;
            }

            str = encodeRecodePrivateKey();
            if (!str.isSuccessful())
            {
                return str;
            }

            str = encodeRecodePublicKey();
            if (!str.isSuccessful())
            {
                return str;
            }


            str = encodeRecodePublicKeyGost2006();
            if (!str.isSuccessful())
            {
                return str;
            }

            str = encodeRecodePrivateKeyGost2006();
            if (!str.isSuccessful())
            {
                return str;
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
    }

    private class GOST3410_TEST1_512
        implements Test
    {
        public String getName()
        {
            return "GOST3410-TEST1-512";
        }

        FixedSecureRandom init_random = new FixedSecureRandom(
            new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(Hex.decode("00005EC900007341")), new FixedSecureRandom.Data(zeroTwo(64))});
        FixedSecureRandom random = new TestRandomData(Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A"));
        FixedSecureRandom keyRandom = new TestRandomData(Hex.decode("3036314538303830343630454235324435324234314132373832433138443046"));

        BigInteger pValue = new BigInteger("EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3", 16);
        BigInteger qValue = new BigInteger("98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("3e5f895e276d81d2d52c0763270a458157b784c57abdbd807bc44fd43a32ac06", 16);
            BigInteger s = new BigInteger("3f0dd5d4400d47c08e4ce505ff7434b6dbf729592e37c74856dab85115a60955", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(512, 1, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (params.getValidationParameters() == null)
            {
                return new SimpleTestResult(false, getName() + "validation parameters wrong");
            }
            if (params.getValidationParameters().getC() != 29505
                || params.getValidationParameters().getX0() != 24265)
            {
                return new SimpleTestResult(false, getName() + "validation parameters values wrong");
            }
            if (!init_random.isExhausted())
            {
                return new SimpleTestResult(false, getName()
                    + ": unexpected number of bytes used from 'init_random'.");
            }

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            if (!keyRandom.isExhausted())
            {
                return new SimpleTestResult(false, getName()
                    + ": unexpected number of bytes used from 'keyRandom'.");
            }

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer gost3410 = new GOST3410Signer();

            gost3410.init(true, param);

            BigInteger[] sig = gost3410.generateSignature(hashmessage);

            if (!random.isExhausted())
            {
                return new SimpleTestResult(false, getName()
                    + ": unexpected number of bytes used from 'random'.");
            }

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            gost3410.init(false, pair.getPublic());

            if (gost3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_TEST2_512
        implements Test
    {
        public String getName()
        {
            return "GOST3410-TEST2-512";
        }

        FixedSecureRandom init_random = new FixedSecureRandom(
            new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(Hex.decode("000000003DFC46F1000000000000000D")), new FixedSecureRandom.Data(zeroTwo(64))});
        FixedSecureRandom random = new TestRandomData(Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A"));
        FixedSecureRandom keyRandom = new TestRandomData(Hex.decode("3036314538303830343630454235324435324234314132373832433138443046"));

        BigInteger pValue = new BigInteger("8b08eb135af966aab39df294538580c7da26765d6d38d30cf1c06aae0d1228c3316a0e29198460fad2b19dc381c15c888c6dfd0fc2c565abb0bf1faff9518f85", 16);
        BigInteger qValue = new BigInteger("931a58fb6f0dcdf2fe7549bc3f19f4724b56898f7f921a076601edb18c93dc75", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("7c07c8cf035c2a1cb2b7fae5807ac7cd623dfca7a1a68f6d858317822f1ea00d", 16);
            BigInteger s = new BigInteger("7e9e036a6ff87dbf9b004818252b1f6fc310bdd4d17cb8c37d9c36c7884de60c", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(512, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!init_random.isExhausted())
            {
                return new SimpleTestResult(false, getName()
                    + ": unexpected number of bytes used from 'init_random'.");
            }

            if (params.getValidationParameters() == null)
            {
                return new SimpleTestResult(false, getName() + ": validation parameters wrong");
            }

            if (params.getValidationParameters().getCL() != 13
                || params.getValidationParameters().getX0L() != 1039943409)
            {
                return new SimpleTestResult(false, getName() + ": validation parameters values wrong");
            }

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            if (!keyRandom.isExhausted())
            {
                return new SimpleTestResult(false, getName()
                    + ": unexpected number of bytes used from 'keyRandom'.");
            }

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!random.isExhausted())
            {
                return new SimpleTestResult(false, getName()
                    + ": unexpected number of bytes used from 'random'.");
            }

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_TEST1_1024
        implements Test
    {
        public String getName()
        {
            return "GOST3410-TEST1-1024";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstInt = true;

            public int nextInt()
            {
                String x0 = "0xA565";
                String c = "0x538B";

                if (firstInt)
                {
                    firstInt = false;
                    return NumberParsing.decodeIntFromHex(x0);
                }
                return NumberParsing.decodeIntFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {

                byte[] d = Hex.decode("02");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("ab8f37938356529e871514c1f48c5cbce77b2f4fc9a2673ac2c1653da8984090c0ac73775159a26bef59909d4c9846631270e16653a6234668f2a52a01a39b921490e694c0f104b58d2e14970fccb478f98d01e975a1028b9536d912de5236d2dd2fc396b77153594d4178780e5f16f718471e2111c8ce64a7d7e196fa57142d", 16);
        BigInteger qValue = new BigInteger("bcc02ca0ce4f0753ec16105ee5d530aa00d39f3171842ab2c334a26b5f576e0f", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("a8790aabbd5a998ff524bad048ac69cd1faff2dab048265c8d60d1471c44a9ee", 16);
            BigInteger s = new BigInteger("30df5ba32ac77170b9632559bef7d37620017756dff3fea1088b4267db0944b8", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 1, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_TEST2_1024
        implements Test
    {
        public String getName()
        {
            return "GOST3410-TEST2-1024";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0x3DFC46F1";
                String c = "0xD";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {

                byte[] d = Hex.decode("02");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("e2c4191c4b5f222f9ac2732562f6d9b4f18e7fb67a290ea1e03d750f0b9806755fc730d975bf3faa606d05c218b35a6c3706919aab92e0c58b1de4531c8fa8e7af43c2bff016251e21b2870897f6a27ac4450bca235a5b748ad386e4a0e4dfcb09152435abcfe48bd0b126a8122c7382f285a9864615c66decddf6afd355dfb7", 16);
        BigInteger qValue = new BigInteger("931a58fb6f0dcdf2fe7549bc3f19f4724b56898f7f921a076601edb18c93dc75", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("81d69a192e9c7ac21fc07da41bd07e230ba6a94eb9f3c1fd104c7bd976733ca5", 16);
            BigInteger s = new BigInteger("315c879c8414f35feb4deb15e7cc0278c48e6ca1596325d6959338d860b0c47a", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_AParam
        implements Test
    {
        public String getName()
        {
            return "GOST3410-AParam";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0x520874F5";
                String c = "0xEE39ADB3";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {

                byte[] d = Hex.decode("02");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("b4e25efb018e3c8b87505e2a67553c5edc56c2914b7e4f89d23f03f03377e70a2903489dd60e78418d3d851edb5317c4871e40b04228c3b7902963c4b7d85d52b9aa88f2afdbeb28da8869d6df846a1d98924e925561bd69300b9ddd05d247b5922d967cbb02671881c57d10e5ef72d3e6dad4223dc82aa1f7d0294651a480df", 16);
        BigInteger qValue = new BigInteger("972432a437178b30bd96195b773789ab2fff15594b176dd175b63256ee5af2cf", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("64a8856628e5669d85f62cd763dd4a99bc56d33dc0e1859122855d141e9e4774", 16);
            BigInteger s = new BigInteger("319ebac97092b288d469a4b988248794f60c865bc97858d9a3135c6d1a1bf2dd", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_BParam
        implements Test
    {
        public String getName()
        {
            return "GOST3410-BParam";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0x5B977CDB";
                String c = "0x6E9692DD";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {
                byte[] d = Hex.decode("bc3cbbdb7e6f848286e19ad9a27a8e297e5b71c53dd974cdf60f937356df69cbc97a300ccc71685c553046147f11568c4fddf363d9d886438345a62c3b75963d6546adfabf31b31290d12cae65ecb8309ef66782");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("c6971fc57524b30c9018c5e621de15499736854f56a6f8aee65a7a404632b3540f09020f67f04dc2e6783b141dceffd21a703035b7d0187c6e12cb4229922bafdb2225b73e6b23a0de36e20047065aea000c1a374283d0ad8dc1981e3995f0bb8c72526041fcb98ae6163e1e71a669d8364e9c4c3188f673c5f8ee6fadb41abf", 16);
        BigInteger qValue = new BigInteger("b09d634c10899cd7d4c3a7657403e05810b07c61a688bab2c37f475e308b0607", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("860d82c60e9502cd00c0e9e1f6563feafec304801974d745c5e02079946f729e", 16);
            BigInteger s = new BigInteger("7ef49264ef022801aaa03033cd97915235fbab4c823ed936b0f360c22114688a", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_CParam
        implements Test
    {
        public String getName()
        {
            return "GOST3410-CParam";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0x43848744";
                String c = "0xB50A826D";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {
                byte[] d = Hex.decode("7F575E8194BC5BDF");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("9d88e6d7fe3313bd2e745c7cdd2ab9ee4af3c8899e847de74a33783ea68bc30588ba1f738c6aaf8ab350531f1854c3837cc3c860ffd7e2e106c3f63b3d8a4c034ce73942a6c3d585b599cf695ed7a3c4a93b2b947b7157bb1a1c043ab41ec8566c6145e938a611906de0d32e562494569d7e999a0dda5c879bdd91fe124df1e9", 16);
        BigInteger qValue = new BigInteger("fadd197abd19a1b4653eecf7eca4d6a22b1f7f893b641f901641fbb555354faf", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("4deb95a0b35e7ed7edebe9bef5a0f93739e16b7ff27fe794d989d0c13159cfbc", 16);
            BigInteger s = new BigInteger("e1d0d30345c24cfeb33efde3deee5fbbda78ddc822b719d860cd0ba1fb6bd43b", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_DParam
        implements Test
    {
        public String getName()
        {
            return "GOST3410-DParam";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0x13DA8B9D";
                String c = "0xA0E9DE4B";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {

                byte[] d = Hex.decode("41ab97857f42614355d32db0b1069f109a4da283676c7c53a68185b4");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("80f102d32b0fd167d069c27a307adad2c466091904dbaa55d5b8cc7026f2f7a1919b890cb652c40e054e1e9306735b43d7b279eddf9102001cd9e1a831fe8a163eed89ab07cf2abe8242ac9dedddbf98d62cddd1ea4f5f15d3a42a6677bdd293b24260c0f27c0f1d15948614d567b66fa902baa11a69ae3bceadbb83e399c9b5", 16);
        BigInteger qValue = new BigInteger("f0f544c418aac234f683f033511b65c21651a6078bda2d69bb9f732867502149", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("712592d285b792e33b8a9a11e8e6c4f512ddf0042972bbfd1abb0a93e8fc6f54", 16);
            BigInteger s = new BigInteger("2cf26758321258b130d5612111339f09ceb8668241f3482e38baa56529963f07", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_AExParam
        implements Test
    {
        public String getName()
        {
            return "GOST3410-AExParam";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0xD05E9F14";
                String c = "0x46304C5F";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {
                byte[] d = Hex.decode("35ab875399cda33c146ca629660e5a5e5c07714ca326db032dd6751995cdb90a612b9228932d8302704ec24a5def7739c5813d83");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("ca3b3f2eee9fd46317d49595a9e7518e6c63d8f4eb4d22d10d28af0b8839f079f8289e603b03530784b9bb5a1e76859e4850c670c7b71c0df84ca3e0d6c177fe9f78a9d8433230a883cd82a2b2b5c7a3306980278570cdb79bf01074a69c9623348824b0c53791d53c6a78cab69e1cfb28368611a397f50f541e16db348dbe5f", 16);
        BigInteger qValue = new BigInteger("cae4d85f80c147704b0ca48e85fb00a9057aa4acc44668e17f1996d7152690d9", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("90892707282f433398488f19d31ac48523a8e2ded68944e0da91c6895ee7045e", 16);
            BigInteger s = new BigInteger("3be4620ee88f1ee8f9dd63c7d145b7e554839feeca125049118262ea4651e9de", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    public String getName()
    {
        return "GOST3410";
    }

    private class GOST3410_BExParam
        implements Test
    {
        public String getName()
        {
            return "GOST3410-BExParam";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0x7A007804";
                String c = "0xD31A4FF7";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {
                byte[] d = Hex.decode("7ec123d161477762838c2bea9dbdf33074af6d41d108a066a1e7a07ab3048de2");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("9286dbda91eccfc3060aa5598318e2a639f5ba90a4ca656157b2673fb191cd0589ee05f4cef1bd13508408271458c30851ce7a4ef534742bfb11f4743c8f787b11193ba304c0e6bca25701bf88af1cb9b8fd4711d89f88e32b37d95316541bf1e5dbb4989b3df13659b88c0f97a3c1087b9f2d5317d557dcd4afc6d0a754e279", 16);
        BigInteger qValue = new BigInteger("c966e9b3b8b7cdd82ff0f83af87036c38f42238ec50a876cd390e43d67b6013f", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("8f79a582513df84dc247bcb624340cc0e5a34c4324a20ce7fe3ab8ff38a9db71", 16);
            BigInteger s = new BigInteger("7508d22fd6cbb45efd438cb875e43f137247088d0f54b29a7c91f68a65b5fa85", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    private class GOST3410_CExParam
        implements Test
    {
        public String getName()
        {
            return "GOST3410-CExParam";
        }

        SecureRandom init_random = new SecureRandom()
        {
            boolean firstLong = true;

            public long nextLong()
            {
                String x0 = "0x162AB910";
                String c = "0x93F828D3";

                if (firstLong)
                {
                    firstLong = false;
                    return NumberParsing.decodeLongFromHex(x0);
                }
                return NumberParsing.decodeLongFromHex(c);
            }

            public void nextBytes(byte[] bytes)
            {
                byte[] d = Hex.decode("ca82cce78a738bc46f103d53b9bf809745ec845e4f6da462606c51f60ecf302e31204b81");

                System.arraycopy(d, 0, bytes, bytes.length - d.length, d.length);
            }
        };

        SecureRandom random = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = Hex.decode("90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A");

                int i;

                for (i = 0; i < (bytes.length - k.length); i += k.length)
                {
                    System.arraycopy(k, 0, bytes, i, k.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(k, 0, bytes, i - k.length, bytes.length - (i - k.length));
                }
                else
                {
                    System.arraycopy(k, 0, bytes, i, bytes.length - i);
                }
            }
        };

        SecureRandom keyRandom = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] x = Hex.decode("3036314538303830343630454235324435324234314132373832433138443046");

                int i;

                for (i = 0; i < (bytes.length - x.length); i += x.length)
                {
                    System.arraycopy(x, 0, bytes, i, x.length);
                }

                if (i > bytes.length)
                {
                    System.arraycopy(x, 0, bytes, i - x.length, bytes.length - (i - x.length));
                }
                else
                {
                    System.arraycopy(x, 0, bytes, i, bytes.length - i);
                }
            }
        };

        BigInteger pValue = new BigInteger("b194036ace14139d36d64295ae6c50fc4b7d65d8b340711366ca93f383653908ee637be428051d86612670ad7b402c09b820fa77d9da29c8111a8496da6c261a53ed252e4d8a69a20376e6addb3bdcd331749a491a184b8fda6d84c31cf05f9119b5ed35246ea4562d85928ba1136a8d0e5a7e5c764ba8902029a1336c631a1d", 16);
        BigInteger qValue = new BigInteger("96120477df0f3896628e6f4a88d83c93204c210ff262bccb7dae450355125259", 16);

        public TestResult perform()
        {
            BigInteger r = new BigInteger("169fdb2dc09f690b71332432bfec806042e258fa9a21dafe73c6abfbc71407d9", 16);
            BigInteger s = new BigInteger("9002551808ae40d19f6f31fb67e4563101243cf07cffd5f2f8ff4c537b0c9866", 16);
            GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

            pGen.init(1024, 2, init_random);

            GOST3410Parameters params = pGen.generateParameters();

            if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
            {
                return new SimpleTestResult(false, getName() + ": p or q wrong");
            }

            GOST3410KeyPairGenerator GOST3410KeyGen = new GOST3410KeyPairGenerator();
            GOST3410KeyGenerationParameters genParam = new GOST3410KeyGenerationParameters(keyRandom, params);

            GOST3410KeyGen.init(genParam);

            AsymmetricCipherKeyPair pair = GOST3410KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            GOST3410Signer GOST3410 = new GOST3410Signer();

            GOST3410.init(true, param);

            BigInteger[] sig = GOST3410.generateSignature(hashmessage);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s.toString(16) + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
            }

            GOST3410.init(false, pair.getPublic());

            if (GOST3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }
}
