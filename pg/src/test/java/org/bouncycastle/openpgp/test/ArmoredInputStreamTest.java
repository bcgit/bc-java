package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ArmoredInputStreamTest
    extends SimpleTest
{
    private static final byte[] bogusData = Hex.decode(
        "ed864b3c622d5d71d43e5bd77876e81bfaaba8522f64cb494dc897daa3494f7da598f5907b758b72394fbefea77b86a16865e7bf" +
            "b8f5bb46bb0d2db4a99a6a4542b9040a0e4f74b8e202c4eb255e8a81a59be9c0d5d2c593b8b512c9bdc75a243cb0992b5a885889" +
            "a4a3d3d70e1fcb415d4f718e8230b11895e3706314912554d7c19dafb733df7d02e9a2f42492139648618b1943af9e2941bd0e42" +
            "73b58de9b734d15a793a6d7673b3e90dedebc2a479965680de61880dddea25c0168237a6e52846e6a5aa9fb9161ac7a3996315cf" +
            "7d391cb86e86cce44e2a353b68cf84d3ac49eddde9a040180533af4aade92de7a03c1982020a2591141aeffd2ad07ffbc0d0a303" +
            "710763f47317a5c468d18e69e4094945060f707778cd65b4e94c2e27b5e5a8f4d510e01c9f84b22e1c59486a9b72552682833a07" +
            "23995febde56a59d31b60b2cdac00efbf693ac27607c8c4a502749bc7bde65ec80c661aadada4611e3093607d8c7927bf4b29ea9" +
            "0481a4616952abb88cb2f4ad78c2e94ba9193f0d0dac17d972ed0b6a738a11a6f27a3a5857e9a0746c5acb2a33ea05491e23db39" +
            "657549b5b1a341f2088232b5c72c1a3fcce6dd8b1ce8ade51977521e473b6b208458ce513606daf47689c9a239e161cc592f070f" +
            "395a2b964547954516651fc122a781b336d3ddc529c37c16022e6882ba52a6ff9ffd1e362971096997053e916953ca6146eb9973" +
            "a28663074692fa3d216b4f169d20e32655602461dce525db1d94b9c43620e05a9e2d3465bb7ed0c07493738434bcf058a73b22ab" +
            "0fd6ade1b995b3129d791e3f3a9446d35d9fe521ba5f196f98e7b637132aaa2df424ddb4e372cb70ede1eacdf0b454de91ae279f" +
            "ec3c16e268f262a169a2d9ecb27ac1ae177fa6f31f63991179b35e5a48d5cd0e369f50f92cf0327bde1cbd8125201b0c0e4c9242" +
            "d416cf48a9ac9c367ab424999fdf3cf5faac259b302b68c417f1461380a57d4f6a5bad8e60ac2140af53f3b44b2e4a44383e597e" +
            "f0d7594d2f8c74346a7759b13364bf7abe08663ed4d2ab92bd60231d71e63c125739c446c048e76b7157c644ad6e136f3078c79a" +
            "27d505af22b25706c4cf1aec5cb9578e0d0f0471fabdbfc4504a4f971b2c68a4af75ff9a438b1e4c3507dd93c38dc8caa43e87c3" +
            "95e27d9b23402671e1a8a6f9563ba8e9d00d2f99d77d25bdda2ac4fe363db138a6eeea4ec1a5ae104cc30b9e4f468799335157da" +
            "a9f4c310ef0806ef1803d81db84f58b45639a1749c705594cf5dbbe6109af4711eb080af4edd0d0386c09676b705d3a0ccad5cc7" +
            "b5f289a884ce649b5b00b46ad33ee43b0db8c0202cf1fdde4c3b61d5fec99e3024016ccdb0ff2d321f08781d08e4312de38245eb" +
            "bc2af032d2a59e36be6467bc23456b4ac178d36cf9f45df5e833a1981ed1a1032679ea0a");

    private static final String badHeaderData1 =
          "-----BEGIN PGP MESSAGE-----\n"
        + "Version: BCPG v1.32\n"
        + "Comment: A dummy message\n"
        + "Comment actually not really as there is no colon"
        + " \t \t\n"
        + "SGVsbG8gV29ybGQh\n"
        + "=d9Xi\n"
        + "-----END PGP MESSAGE-----\n";

    private static final String badHeaderData2 =
          "-----BEGIN PGP MESSAGE-----\n"
        + "Comment actually not really as there is no colon"
        + " \t \t\n"
        + "SGVsbG8gV29ybGQh\n"
        + "=d9Xi\n"
        + "-----END PGP MESSAGE-----\n";

    public String getName()
    {
        return "ArmoredInputStream";
    }

    public void performTest()
        throws Exception
    {
        bogusHeadersTest();
        unknownClearsignedMessageHeadersTest();
    }

    private void bogusHeadersTest()
    {
        try
        {
            PGPObjectFactory pgpObjectFactoryOfTestFile = new PGPObjectFactory(
                new ArmoredInputStream(new ByteArrayInputStream(Arrays.concatenate(Strings.toByteArray("-----BEGIN PGP MESSAGE-----\n"
                        + "Version: BCPG v1.32\n\n"), bogusData))), new JcaKeyFingerprintCalculator());
            pgpObjectFactoryOfTestFile.nextObject(); // <-- EXCEPTION HERE
            fail("no exception");
        }
        catch (IOException e)
        {
            isTrue("invalid armor".equals(e.getMessage()));
        }

        try
        {
            PGPObjectFactory pgpObjectFactoryOfTestFile = new PGPObjectFactory(
                new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(badHeaderData1))), new JcaKeyFingerprintCalculator());
            fail("no exception");
        }
        catch (IOException e)
        {
            isTrue("invalid armor header".equals(e.getMessage()));
        }

        try
        {
            PGPObjectFactory pgpObjectFactoryOfTestFile = new PGPObjectFactory(
                new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(badHeaderData2))), new JcaKeyFingerprintCalculator());
            fail("no exception");
        }
        catch (IOException e)
        {
            isTrue("invalid armor header".equals(e.getMessage()));
        }
    }

    private void unknownClearsignedMessageHeadersTest() throws IOException {
        // https://sequoia-pgp.gitlab.io/openpgp-interoperability-test-suite/results.html#Mangled_message_using_the_Cleartext_Signature_Framework_
        String armor = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "Hello: this is totally part of the signed text\n" +
                "Hash: SHA512\n" +
                "\n" +
                "- From the grocery store we need:\n" +
                "\n" +
                "- - tofu\n" +
                "- - vegetables\n" +
                "- - noodles\n" +
                "\n" +
                "\n" +
                "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAEBCgBvBYJoMZ08CRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmeO1uFIMk5ydOB8SNGi9ZkD0sHEoFRZM20v669ghBur\n" +
                "KBYhBNGmbhojsYLJmA94jPv8yCoBXnMwAACffQwArOoXVWEF/Yii182hZPqE6t/E\n" +
                "ZEyJcZLwsJXQ00ctno0TjXY9iDS0l1i0cWVIIcgkoutd+Gn8XI30EQEJivAs8uvE\n" +
                "yCDFRQgkag2kOn+QtawyQ3LO+Xd5oZDbcy9Jvf4sG5YobBs7kfTb2NQgXDViM+k3\n" +
                "69je5Mj+oKhtckM3BROYxq+B8DPgPT9UJuz0UgFQVYm5Mjj9jnFlUbMVl7UnsZwP\n" +
                "0RNnbW8jtuQn7ehePzAOB94bzkvJL8/obPw2LsDfC0gWTovpJo0JibPZD/zaTA4y\n" +
                "7yLnRvEM+8PilR6eIY40Us9oJerpjYsA16WMyIEvRfgHrYITpqHEzpJa7/vnMF2g\n" +
                "t2PjcdtFeBsmJZrLwaJWB5Tku6wMsVL8Rmit8qecnVg9qYL3FrRUweEGo/dAH49M\n" +
                "udZeck+sMaXdIhJnwy4HnH0tUiEGnHQ5mnBtTvKFR98paDVIW/xS+o95hUfmAXA8\n" +
                "rmMglLYQkIXAZayAquW+VrxSxglNqXYxZNIxuHT6\n" +
                "=yj77\n" +
                "-----END PGP SIGNATURE-----";

        // Test validation is not enabled by default
        ByteArrayInputStream bIn = new ByteArrayInputStream(armor.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = ArmoredInputStream.builder()
                .build(bIn);
        // Skip over cleartext
        isTrue(aIn.isClearText());
        while (aIn.isClearText()) {
            aIn.read();
        }
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigs = (PGPSignatureList) objFac.nextObject();
        isTrue(sigs != null);


        // Test validation enabled
        bIn = new ByteArrayInputStream(armor.getBytes(StandardCharsets.UTF_8));
        ByteArrayInputStream finalBIn = bIn;
        isTrue(null != testException(
                "Illegal ASCII armor header line in clearsigned message encountered: Hello: this is totally part of the signed text",
                "ArmoredInputException",
                new TestExceptionOperation()
                {
                    @Override
                    public void operation() throws Exception
                    {
                        ArmoredInputStream.builder()
                                .setValidateClearsignedMessageHeaders(true)
                                .build(finalBIn);
                    }
                })
        );


        // Test validation enabled, but custom header allowed
        bIn = new ByteArrayInputStream(armor.getBytes(StandardCharsets.UTF_8));
        aIn = ArmoredInputStream.builder()
                .setValidateClearsignedMessageHeaders(true)
                .addAllowedArmorHeader("Hello")
                .build(bIn);
        // Skip over cleartext
        isTrue(aIn.isClearText());
        while (aIn.isClearText()) {
            aIn.read();
        }
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        sigs = (PGPSignatureList) objFac.nextObject();
        isTrue(sigs != null);
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ArmoredInputStreamTest());
    }
}
