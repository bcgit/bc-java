package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class PGPEncryptedDataTest
    extends SimpleTest
{
    @Override
    public String getName()
    {
        return "PGPEncryptedData";
    }

    @Override
    public void performTest()
        throws Exception
    {
        // AEAD Test
        byte[] key = Base64.decode("lIYEYtpQnxYJKwYBBAHaRw8BAQdA207jla1mpSFwMxffhBxMCar0p8rogMEoeLJd\n" +
            "sCPM0tn+BwMCpoW0UFliSk3SkECmD5cAbHhojoHeiCmT1xmGLt7PIkzzhX6/t96n\n" +
            "arb3JTQMOWltqbt8gLuRjdRuYmliUcPr19SPvepnvqhwLqcOEbbQorQbVGVzdCBU\n" +
            "ZXN0ZXIgPHRlc3RAdGVzdC5jb20+iJkEExYIAEEWIQSqx6vJaSbUECwYQX+L2Dcj\n" +
            "JcwH4AUCYtpQnwIbAwUJA8JnAAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAK\n" +
            "CRCL2DcjJcwH4BQaAQDxal5Q37MSY5EIauKat5fW8j76EwWbMQKadU44Aud2MQD9\n" +
            "FpYCHOh9TkNRfnmnImoxSmeSM0FJOORtPTgh6sxb1QmciwRi2lCfEgorBgEEAZdV\n" +
            "AQUBAQdAkrGtbXYvPKFZBwH6WiFKFE1z+0QplQQMFGlPn4oLUXMDAQgH/gcDAj+y\n" +
            "CtAcASIU0hkO9Ua0ZPO7jyCpQIuI62G5CAUOZTxtnnWOZmmveiJyFu8Vlow4CJoS\n" +
            "KaHc+UeCEPnlb1zLNTW9Icc+OTr/G3HeAKKRM9mIfgQYFggAJhYhBKrHq8lpJtQQ\n" +
            "LBhBf4vYNyMlzAfgBQJi2lCfAhsMBQkDwmcAAAoJEIvYNyMlzAfgMZgA/Ani2Xh2\n" +
            "tU49kjLEFGW4tFOy5PLI8yqqhqDgTdHXo5b5APsH4Q2+dTJdJOzEXsPtlRtwijdA\n" +
            "XNOF3zCe4gEzYO3KDw==");
        byte[] msg = Base64.decode("hE4D4e5Iwh6WdeASAQdA9DbvpCwdd9KykHdl1L/pvbSeuFWzhCLoCibP7+WCM2Ag\n" +
            "ut1kdKQcPo87xfRybK+LM1esJLfY++R9Lx+KxblnKInUVwEHAhBIb1CMxge1v4iZ\n" +
            "SkwYIE/J8MjOyHtwM0koCtKY0Vq8D6LSmLXNCmBvYuqRDOEaJLHiq++RHMrEv7oT\n" +
            "o41RqX9OLFu4/ZAwoL1mABtJIy0B2teibg==");

        PGPSecretKeyRing rng = new PGPSecretKeyRing(new ByteArrayInputStream(key), new JcaKeyFingerprintCalculator());
        PGPObjectFactory oIn = new JcaPGPObjectFactory(new ByteArrayInputStream(msg));

        PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(rng.getSecretKey(encP.getKeyID()).extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("Test".toCharArray()))));

        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

        isEquals("wrong filename", "Test.txt", ld.getFileName());

        byte[] data = Streams.readAll(ld.getDataStream());

        isTrue(Arrays.areEqual(Strings.toByteArray("Test Content"), data));
    }
    
    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPEncryptedDataTest());
    }
}
