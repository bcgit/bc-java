package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricEncDataPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class PKESKv6withSEIPDv2Test extends SimpleTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: AFD1 BCC8 B315 4C2D F07B  D009 D55C 5DC3 89E1 4441\n" +
            "Comment: Alice <alice@example.com>\n" +
            "\n" +
            "xVgEZGs/QRYJKwYBBAHaRw8BAQdAfgVCImtT9L3hNcl41KMzoO8A/kzlXc8fHS5h\n" +
            "Z8MSO4wAAQCYOyC725WGBoIj7a0VLMOsjmUFLwKyG1/puUTJDPgOLw3fwsARBB8W\n" +
            "CgCDBYJkaz9BBYkFn6YAAwsJBwkQ1Vxdw4nhREFHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
            "dGlvbnMuc2VxdW9pYS1wZ3Aub3Jngu9XU/ofLgbPYwUu0xZVaP8FegCfZahtJthB\n" +
            "gDZBBrIDFQoIApsBAh4BFiEEr9G8yLMVTC3we9AJ1Vxdw4nhREEAAEoBAQDmGcTE\n" +
            "rxnLRxWB+g4OJFNKz8ugNbrC9koHWM+sb4EMOAD/cMH+V7K8DcBGQnWlQPRgbIVf\n" +
            "fAt/hcZGBHH3euVRqgnNGUFsaWNlIDxhbGljZUBleGFtcGxlLmNvbT7CwBQEExYK\n" +
            "AIYFgmRrP0EFiQWfpgADCwkHCRDVXF3DieFEQUcUAAAAAAAeACBzYWx0QG5vdGF0\n" +
            "aW9ucy5zZXF1b2lhLXBncC5vcmcRKvM0qlMbMcBop8d1wzBDMq/098RfSgTRmuSu\n" +
            "MwW3WAMVCggCmQECmwECHgEWIQSv0bzIsxVMLfB70AnVXF3DieFEQQAAhw4A+gJ7\n" +
            "oxMYtwkYX25x3HtbcOJJBa71rQk+q4aqmd8bzfe4AP4nD3tszbAljDx8/4Qtz62B\n" +
            "56kma/1cHFhajc66R8bWCsdYBGRrP0EWCSsGAQQB2kcPAQEHQE4WSMzZ/yoheDyr\n" +
            "eDwF0SJlLV0ddJEeW6NUNdUWiTcOAAD/WJn6fcf/RexsTOvQGG+uOE8VeEkF/7F3\n" +
            "01WrwIkmZpARx8LAxQQYFgoBNwWCZGs/QQWJBZ+mAAkQ1Vxdw4nhREFHFAAAAAAA\n" +
            "HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn9ATNlZD1e4/RxvvMkaWz\n" +
            "l9zRrKfAMtKfglrqh8RI35oCmwK+oAQZFgoAbwWCZGs/QQkQ5QYZf0wPkGdHFAAA\n" +
            "AAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnZATAIan64zoHbAg3\n" +
            "LR+cpvi4fF7z7/dkFfsnjwFryMsWIQTdCNn4kFgnatKPGRTlBhl/TA+QZwAAEPgB\n" +
            "ALIZ2y1F5aOtvXVeDXbE+VdOid+JOGXd+CfDE1/GleGdAQDWOcwGjJOsELTipOH1\n" +
            "5yYjna84zzRTmrzfFfizPithCxYhBK/RvMizFUwt8HvQCdVcXcOJ4URBAAD9GQD/\n" +
            "WSrWy/VR1SCfkM5LjVsdnet1wtS5YjkRK3i+kZevn8kBAIxJdvKzUEnDpr7wVANm\n" +
            "yNHBbMzoGRLE1ow9HLMHFiwOx10EZGs/QRIKKwYBBAGXVQEFAQEHQGWXj+d6BAXO\n" +
            "aEXHbHTKBQCORPOSARwT2ZGNwofwFLZaAwEIBwAA/3C7Uuq4SMxzB+Z8CjAL1+zB\n" +
            "XVvlWKxUcaLYn/bnwtm4E4bCwAYEGBYKAHgFgmRrP0EFiQWfpgAJENVcXcOJ4URB\n" +
            "RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZzPwMSDEoCIZ\n" +
            "ubxPG7GHuWoNWenTvSStTvIEZnGJDNB2ApsMFiEEr9G8yLMVTC3we9AJ1Vxdw4nh\n" +
            "REEAACrnAQD3PR869yld7Iy/DTYtLDe97oaxMGBxk7hmxwykcc4YMAEAljoNFOJ4\n" +
            "LQ+YDOP3vmBYCjGDYLWwHEefsbUKYOg3jw4=\n" +
            "=lN6G\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: AFD1 BCC8 B315 4C2D F07B  D009 D55C 5DC3 89E1 4441\n" +
            "Comment: Alice <alice@example.com>\n" +
            "\n" +
            "xjMEZGs/QRYJKwYBBAHaRw8BAQdAfgVCImtT9L3hNcl41KMzoO8A/kzlXc8fHS5h\n" +
            "Z8MSO4zCwBEEHxYKAIMFgmRrP0EFiQWfpgADCwkHCRDVXF3DieFEQUcUAAAAAAAe\n" +
            "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeC71dT+h8uBs9jBS7TFlVo\n" +
            "/wV6AJ9lqG0m2EGANkEGsgMVCggCmwECHgEWIQSv0bzIsxVMLfB70AnVXF3DieFE\n" +
            "QQAASgEBAOYZxMSvGctHFYH6Dg4kU0rPy6A1usL2SgdYz6xvgQw4AP9wwf5XsrwN\n" +
            "wEZCdaVA9GBshV98C3+FxkYEcfd65VGqCc0ZQWxpY2UgPGFsaWNlQGV4YW1wbGUu\n" +
            "Y29tPsLAFAQTFgoAhgWCZGs/QQWJBZ+mAAMLCQcJENVcXcOJ4URBRxQAAAAAAB4A\n" +
            "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZxEq8zSqUxsxwGinx3XDMEMy\n" +
            "r/T3xF9KBNGa5K4zBbdYAxUKCAKZAQKbAQIeARYhBK/RvMizFUwt8HvQCdVcXcOJ\n" +
            "4URBAACHDgD6AnujExi3CRhfbnHce1tw4kkFrvWtCT6rhqqZ3xvN97gA/icPe2zN\n" +
            "sCWMPHz/hC3PrYHnqSZr/VwcWFqNzrpHxtYKzjMEZGs/QRYJKwYBBAHaRw8BAQdA\n" +
            "ThZIzNn/KiF4PKt4PAXRImUtXR10kR5bo1Q11RaJNw7CwMUEGBYKATcFgmRrP0EF\n" +
            "iQWfpgAJENVcXcOJ4URBRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
            "cGdwLm9yZ/QEzZWQ9XuP0cb7zJGls5fc0aynwDLSn4Ja6ofESN+aApsCvqAEGRYK\n" +
            "AG8FgmRrP0EJEOUGGX9MD5BnRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVv\n" +
            "aWEtcGdwLm9yZ2QEwCGp+uM6B2wINy0fnKb4uHxe8+/3ZBX7J48Ba8jLFiEE3QjZ\n" +
            "+JBYJ2rSjxkU5QYZf0wPkGcAABD4AQCyGdstReWjrb11Xg12xPlXTonfiThl3fgn\n" +
            "wxNfxpXhnQEA1jnMBoyTrBC04qTh9ecmI52vOM80U5q83xX4sz4rYQsWIQSv0bzI\n" +
            "sxVMLfB70AnVXF3DieFEQQAA/RkA/1kq1sv1UdUgn5DOS41bHZ3rdcLUuWI5ESt4\n" +
            "vpGXr5/JAQCMSXbys1BJw6a+8FQDZsjRwWzM6BkSxNaMPRyzBxYsDs44BGRrP0ES\n" +
            "CisGAQQBl1UBBQEBB0Bll4/negQFzmhFx2x0ygUAjkTzkgEcE9mRjcKH8BS2WgMB\n" +
            "CAfCwAYEGBYKAHgFgmRrP0EFiQWfpgAJENVcXcOJ4URBRxQAAAAAAB4AIHNhbHRA\n" +
            "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZzPwMSDEoCIZubxPG7GHuWoNWenTvSSt\n" +
            "TvIEZnGJDNB2ApsMFiEEr9G8yLMVTC3we9AJ1Vxdw4nhREEAACrnAQD3PR869yld\n" +
            "7Iy/DTYtLDe97oaxMGBxk7hmxwykcc4YMAEAljoNFOJ4LQ+YDOP3vmBYCjGDYLWw\n" +
            "HEefsbUKYOg3jw4=\n" +
            "=02w7\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @Override
    public String getName() {
        return "PKESKv6withSEIPDv2Test";
    }

    @Override
    public void performTest() throws Exception {
        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        PGPPublicKeyRing publicKeys = readCert(CERT);
        PGPPublicKey encKey = publicKeys.getPublicKey(5939832804746992246L);

        PGPDataEncryptorBuilder dataEncBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        dataEncBuilder.setUseV6AEAD();
        dataEncBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(dataEncBuilder);
        PublicKeyKeyEncryptionMethodGenerator method = new BcPublicKeyKeyEncryptionMethodGenerator(encKey, true);
        encGen.addMethod(method);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        OutputStream encOut = encGen.open(armorOut, new byte[8192]);
        OutputStream litOut = litGen.open(encOut, PGPLiteralData.TEXT, "", PGPLiteralData.NOW, new byte[8192]);

        litOut.write(data);
        litOut.close();
        encOut.close();
        armorOut.close();

        System.out.println(out.toString());

        PGPSecretKeyRing secretKeys = readKey(KEY);
        PGPSecretKey decryptionKey = secretKeys.getSecretKey(5939832804746992246L);
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);

        ByteArrayInputStream bIn = new ByteArrayInputStream(out.toByteArray());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPEncryptedDataList encDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encDataList.get(0);

        PublicKeyDataDecryptorFactory decryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
        InputStream decIn = encData.getDataStream(decryptorFactory);
        objectFactory = new BcPGPObjectFactory(decIn);
        PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();
        ByteArrayOutputStream decOut = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), decOut);

        isTrue(Arrays.areEqual(data, decOut.toByteArray()));
    }

    public static void main(String[] args) {
        runTest(new PKESKv6withSEIPDv2Test());
    }

    private PGPPublicKeyRing readCert(String cert) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        return new PGPPublicKeyRing(armorIn, new BcKeyFingerprintCalculator());
    }

    private PGPSecretKeyRing readKey(String key) throws IOException, PGPException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        return new PGPSecretKeyRing(armorIn, new BcKeyFingerprintCalculator());
    }
}
