package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Hashtable;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class ArmoredOutputStreamTest
    extends SimpleTest
{
    byte[] publicKey = Base64.decode(
        "mQELBEQh2+wBCAD26kte0hO6flr7Y2aetpPYutHY4qsmDPy+GwmmqVeCDkX+"
            + "r1g7DuFbMhVeu0NkKDnVl7GsJ9VarYsFYyqu0NzLa9XS2qlTIkmJV+2/xKa1"
            + "tzjn18fT/cnAWL88ZLCOWUr241aPVhLuIc6vpHnySpEMkCh4rvMaimnTrKwO"
            + "42kgeDGd5cXfs4J4ovRcTbc4hmU2BRVsRjiYMZWWx0kkyL2zDVyaJSs4yVX7"
            + "Jm4/LSR1uC/wDT0IJJuZT/gQPCMJNMEsVCziRgYkAxQK3OWojPSuv4rXpyd4"
            + "Gvo6IbvyTgIskfpSkCnQtORNLIudQSuK7pW+LkL62N+ohuKdMvdxauOnAAYp"
            + "tBNnZ2dnZ2dnZyA8Z2dnQGdnZ2c+iQE2BBMBAgAgBQJEIdvsAhsDBgsJCAcD"
            + "AgQVAggDBBYCAwECHgECF4AACgkQ4M/Ier3f9xagdAf/fbKWBjLQM8xR7JkR"
            + "P4ri8YKOQPhK+VrddGUD59/wzVnvaGyl9MZE7TXFUeniQq5iXKnm22EQbYch"
            + "v2Jcxyt2H9yptpzyh4tP6tEHl1C887p2J4qe7F2ATua9CzVGwXQSUbKtj2fg"
            + "UZP5SsNp25guhPiZdtkf2sHMeiotmykFErzqGMrvOAUThrO63GiYsRk4hF6r"
            + "cQ01d+EUVpY/sBcCxgNyOiB7a84sDtrxnX5BTEZDTEj8LvuEyEV3TMUuAjx1"
            + "7Eyd+9JtKzwV4v3hlTaWOvGro9nPS7YaPuG+RtufzXCUJPbPfTjTvtGOqvEz"
            + "oztls8tuWA0OGHba9XfX9rfgorACAAM=");

    static final byte[] expected = Strings.toByteArray(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mQELBEQh2+wBCAD26kte0hO6flr7Y2aetpPYutHY4qsmDPy+GwmmqVeCDkX+r1g7\n" +
            "DuFbMhVeu0NkKDnVl7GsJ9VarYsFYyqu0NzLa9XS2qlTIkmJV+2/xKa1tzjn18fT\n" +
            "/cnAWL88ZLCOWUr241aPVhLuIc6vpHnySpEMkCh4rvMaimnTrKwO42kgeDGd5cXf\n" +
            "s4J4ovRcTbc4hmU2BRVsRjiYMZWWx0kkyL2zDVyaJSs4yVX7Jm4/LSR1uC/wDT0I\n" +
            "JJuZT/gQPCMJNMEsVCziRgYkAxQK3OWojPSuv4rXpyd4Gvo6IbvyTgIskfpSkCnQ\n" +
            "tORNLIudQSuK7pW+LkL62N+ohuKdMvdxauOnAAYptBNnZ2dnZ2dnZyA8Z2dnQGdn\n" +
            "Z2c+iQE2BBMBAgAgBQJEIdvsAhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQ\n" +
            "4M/Ier3f9xagdAf/fbKWBjLQM8xR7JkRP4ri8YKOQPhK+VrddGUD59/wzVnvaGyl\n" +
            "9MZE7TXFUeniQq5iXKnm22EQbYchv2Jcxyt2H9yptpzyh4tP6tEHl1C887p2J4qe\n" +
            "7F2ATua9CzVGwXQSUbKtj2fgUZP5SsNp25guhPiZdtkf2sHMeiotmykFErzqGMrv\n" +
            "OAUThrO63GiYsRk4hF6rcQ01d+EUVpY/sBcCxgNyOiB7a84sDtrxnX5BTEZDTEj8\n" +
            "LvuEyEV3TMUuAjx17Eyd+9JtKzwV4v3hlTaWOvGro9nPS7YaPuG+RtufzXCUJPbP\n" +
            "fTjTvtGOqvEzoztls8tuWA0OGHba9XfX9rfgorACAAM=\n" +
            "=RmFE\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n");

    public String getName()
    {
        return "ArmoredOutputStream";
    }

    public void performTest()
        throws Exception
    {
        testBuilder();
        testExceptions();
        PGPPublicKeyRing keyRing = new PGPPublicKeyRing(publicKey, new JcaKeyFingerprintCalculator());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ArmoredOutputStream aOut = ArmoredOutputStream.builder().build(bOut);

        aOut.write(keyRing.getEncoded());
        aOut.close();

        byte[] res = bOut.toByteArray();
        StringBuffer sb = new StringBuffer();
        byte lastC = 0;
        for (int i = 0; i != res.length; i++)
        {
            if (lastC == '\r')
            {
                sb.append('\n');
                if (res[i] != '\n')
                {
                    sb.append((char)res[i]);
                }
            }
            else if (res[i] != '\r')
            {
                sb.append((char)res[i]);
            }
            lastC = res[i];
        }

        String result = sb.toString();

        isTrue(Arrays.areEqual(expected, Strings.toByteArray(result)));
    }

    public void testBuilder()
        throws Exception
    {
        PGPPublicKeyRing keyRing = new PGPPublicKeyRing(publicKey, new JcaKeyFingerprintCalculator());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
            .setVersion("GnuPG v1.4.2.1 (GNU/Linux)")
            .setVersion("")
            .setComment("Test comment")
            .setMessageId("Test ID")
            .setCharset("UTF-8")
            .addComment("Test comment2")
            .build(bOut);

        aOut.write(keyRing.getEncoded());

        aOut.close();

        byte[] res = bOut.toByteArray();
//        StringBuffer sb = new StringBuffer();
//        byte lastC = 0;
//        for (int i = 0; i != res.length; i++)
//        {
//            if (lastC == '\r')
//            {
//                sb.append('\n');
//                if (res[i] != '\n')
//                {
//                    sb.append((char)res[i]);
//                }
//            }
//            else if (res[i] != '\r')
//            {
//                sb.append((char)res[i]);
//            }
//            lastC = res[i];
//        }
//
//        String result = sb.toString();
//        System.out.println(result);

        ArmoredInputStream inputStream = new ArmoredInputStream(new ByteArrayInputStream(res));
        isEquals(inputStream.getArmorHeaderLine(), "-----BEGIN PGP PUBLIC KEY BLOCK-----");
        isEquals(4, inputStream.getArmorHeaders().length);

        bOut = new ByteArrayOutputStream();
        aOut = ArmoredOutputStream.builder()
            .build(bOut);

        aOut.write(keyRing.getEncoded());

        aOut.close();

        res = bOut.toByteArray();
        inputStream = new ArmoredInputStream(new ByteArrayInputStream(res));

        isEquals(inputStream.getArmorHeaderLine(), "-----BEGIN PGP PUBLIC KEY BLOCK-----");
        isTrue(inputStream.getArmorHeaders() == null);

        Hashtable<String, String> headers = new Hashtable<String, String>();
        headers.put("Version", "GnuPG v1.4.2.1 (GNU/Linux)");
        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut, headers);
        int[] hashAlgorithms = new int[]{HashAlgorithmTags.MD5,
            HashAlgorithmTags.RIPEMD160,
            HashAlgorithmTags.MD2,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA224,
            HashAlgorithmTags.SHA3_256,
            HashAlgorithmTags.SHA3_256_OLD,
            HashAlgorithmTags.SHA3_384,
            HashAlgorithmTags.SHA3_512,
            HashAlgorithmTags.SHA3_512_OLD,
            HashAlgorithmTags.SHA3_224
        };
        aOut.beginClearText(hashAlgorithms);
        aOut.write(keyRing.getEncoded());
        aOut.close();
        res = bOut.toByteArray();
        inputStream = new ArmoredInputStream(new ByteArrayInputStream(res));
        isEquals(hashAlgorithms.length, inputStream.getArmorHeaders().length);
    }

    public void testExceptions()
    {
        testException("unknown hash algorithm tag in beginClearText: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ArmoredOutputStream aOut = new ArmoredOutputStream(new ByteArrayOutputStream());
                         aOut.beginClearText(HashAlgorithmTags.SM3);
            }
        });

        testException("Armor header value for key ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ArmoredOutputStream aOut = ArmoredOutputStream.builder()
                .setVersion("Text\nText")
                .build(new ByteArrayOutputStream());
            }
        });
    }

    public static void main(String[] args)
    {
        runTest(new ArmoredOutputStreamTest());
    }
}
