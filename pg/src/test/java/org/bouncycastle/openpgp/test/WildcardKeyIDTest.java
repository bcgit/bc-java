package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class WildcardKeyIDTest
    extends SimpleTest
{
    private static final String KEY = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: AD4E FA47 5E86 2A89 8C5E  BC56 5D44 DBEB F4E4 117B\n" +
            "\n" +
            "lFgEZEkKfxYJKwYBBAHaRw8BAQdAB0cQLQkEcOU6jo3x6mND+McUV77OPUA2xqKA\n" +
            "puAmuRYAAPwOLG5loKswF8IEBUm4OwITBEUMuhmhvGQaGu97JZufbQwKiIwEHxYK\n" +
            "AD4FAmRJCn8JEF1E2+v05BF7FiEErU76R16GKomMXrxWXUTb6/TkEXsCngECmwEF\n" +
            "FgIDAQAECwkIBwUVCgkICwAAPHQBAJfSmZKxlHDS1Y33umS8HpYjW/B9esRTf3bc\n" +
            "Ub7/PtM3AP0SjA4rpQ0wNFbDpGfRXC6aBeVpZNzeoBmWBksWT0JSBpxdBGRJCn8S\n" +
            "CisGAQQBl1UBBQEBB0BbkXZSB5nhn2eJZgej6UcfIcaVPd45upEGqd62QvQaIwMB\n" +
            "CAcAAP9iwfvRk4aAsOYs5GFBXqslCJssU8W88oiHZivsZgiHCBEbiHUEGBYKAB0F\n" +
            "AmRJCn8CngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRBdRNvr9OQRe81TAQDcvtfw\n" +
            "vR5Ki/PTVDRcYrhc4cDw7MI0POfOY2JO25QcTwEAyFCmw5kg95P2XwXVaAraYuR8\n" +
            "Z7Okda+X8ZczE4Fb8g+cWARkSQp/FgkrBgEEAdpHDwEBB0AOfElGRkuSVLs0yQiv\n" +
            "pxxg92lBZ46d1tpjfPEQKVOdJgABALGt/JUY7QhnMap4cHLj/jGL4vcqIkfQyBUV\n" +
            "mYKVhTwhD/aI1QQYFgoAfQUCZEkKfwKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAE\n" +
            "GRYKAAYFAmRJCn8ACgkQARi+8u3za5yGwAEAkpAi4bXucKmr4jfE6oQMUhGJBkqt\n" +
            "gp8LEqeFFkKYbhIA/iDA1yKlotXC4ifQ9JheoUcvu0nmwZ6AV1JgLNhL0eILAAoJ\n" +
            "EF1E2+v05BF79x4BANMB7+I9vZTSQgbUVw/NebThGKHuvJ0tUayWkIM1j0hsAQD6\n" +
            "yfialgAOd9q4TWt53oD3Z2aDo2dTnjP9GaABP+vJAw==\n" +
            "=u/tO\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String PLAINTEXT = "Hello, World!\n";

    @Override
    public String getName()
    {
        return "WildcardKeyIDTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        ByteArrayInputStream keyBytesIn = new ByteArrayInputStream(Strings.toByteArray(KEY));
        ArmoredInputStream keyArmorIn = new ArmoredInputStream(keyBytesIn);
        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(keyArmorIn, new BcKeyFingerprintCalculator());
        long encryptionKeyId = 7405306990825650521L;

        // Encrypt message
        PGPDataEncryptorBuilder dataEncBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        PGPEncryptedDataGenerator encDataGen = new PGPEncryptedDataGenerator(dataEncBuilder);
        PublicKeyKeyEncryptionMethodGenerator pkeMethodGen = new BcPublicKeyKeyEncryptionMethodGenerator(
                secretKeys.getPublicKey(encryptionKeyId));
        pkeMethodGen.setUseWildcardKeyID(true);
        encDataGen.addMethod(pkeMethodGen);
        ByteArrayOutputStream cipherTextOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(cipherTextOut);
        OutputStream encOut = encDataGen.open(armorOut, new byte[512]);
        PGPLiteralDataGenerator litDataGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litDataGen.open(encOut, PGPLiteralDataGenerator.TEXT, "", new Date(0L), new byte[512]);

        litOut.write(Strings.toByteArray(PLAINTEXT));
        litOut.flush();
        litOut.close();

        encOut.flush();
        encOut.close();

        armorOut.flush();
        armorOut.close();

        // Decrpyt
        PGPSecretKey secretKey = secretKeys.getSecretKey(encryptionKeyId);
        PGPDigestCalculatorProvider digestCalcProv = new BcPGPDigestCalculatorProvider();
        PBESecretKeyDecryptor keyDecryptor = new BcPBESecretKeyDecryptorBuilder(digestCalcProv)
                .build(null);
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(keyDecryptor);

        ByteArrayInputStream cipherTextIn = new ByteArrayInputStream(cipherTextOut.toByteArray());
        ArmoredInputStream armorIn = new ArmoredInputStream(cipherTextIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPEncryptedDataList encDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        PGPPublicKeyEncryptedData pkeData = (PGPPublicKeyEncryptedData) encDataList.get(0);

        isEquals(PublicKeyKeyEncryptionMethodGenerator.WILDCARD, pkeData.getKeyID());

        InputStream decryptedIn = pkeData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
        objectFactory = new BcPGPObjectFactory(decryptedIn);
        PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();
        ByteArrayOutputStream plainTextOut = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), plainTextOut);

        isEquals(PLAINTEXT, plainTextOut.toString());
    }

    public static void main(String[] args)
    {
        runTest(new WildcardKeyIDTest());
    }
}
