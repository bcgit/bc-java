package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.pqc.crypto.newhope.NHAgreement;
import org.bouncycastle.pqc.crypto.newhope.NHExchangePairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHOtherInfoGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class NewHopeTest
    extends SimpleTest
{
//    private static final byte[] SECRETA = Hex.decode(
//        "0823190c27cf2066195d13721d702f1e2248309e124927d5182f175e348a1e800791357825800808223e236e22c41d4e081a2499139e238814590f3d296e34d7"
//            + "1eaa25fb37aa2dac36fa0bba1b0b113616df29a620150bdb12071636186c27ae1546264f33182e4e11330d8e3024138d2dff18de0f411d930f2f11840a6d1e3c"
//            + "0b0b18a81a8014eb364514f00c3a1ab41295314233e2167b049c3481103f243910ac1eaf16da23322b83227738f02b4d26782f8d0e542e04087319981c760ba8"
//            + "329c303f1b0223b429050ef8121220772cc91355309a36051da5282318fe34c60e7034872b10188e2bc1338e0e890a6a13e508cb12dc261d34bb15950fe82f32"
//            + "1cc8090413ec2c1127b1369b28cd0ada154d307a0e582b85240e24e525af20371d6d0c7e0dcb08b60cc023f10afe166323230f3a0a87279f0cd70e8d29b22c95"
//            + "160d13be312131b032103349346e324f1ff812001770269e31c0251a0ab4221a1cdd2d93215b226d19a12cb407cc287c11d821a00a8022182d1725cb13a50d79"
//            + "303d1d680d111367188932891d771f552fb014d62d0214d534b023a70da30c753212167608ae1ac72e4d26c917491bb1204f23b734eb20171a1e26ae22ae2715"
//            + "116933b60cce1d3717701d051d980b9512ca0eb1189e188f0e2c2cd30c800c6024b310d732d6124723c207b5184818e4308f1c1e22921dee32a91f4a0b8b2e28"
//            + "2c290685063f192628701d701d68196f284a2664234d1aa42af7120d1b2532b3168930aa26a51acf2a8214a50c6b330e059315e205c6297f2fc10d420f8d0680"
//            + "28652c0b1119307f09a30b881d5709d52b6e2a2e1eeb19260f521c77066c18ce27262f0b048428ab1eb20ee71e9c066408b909a5275a09da2ebe254b176518ba"
//            + "12e723df13ef152d1d112d700e1622681fa1310a2000138b09f8315622612e492df60d222a430bac2abd06e125a91e1907c92c3a19f829312a6f2dad0aca1772"
//            + "03f1142b0b2f0bfd17a009c60eb913fe32c908590e8f300521dd31880f2b12a8215f1dfa1d8f168228730fc11ae80ca015da0bd412271c8827512325311b1b83"
//            + "1ef2227723b605af2d7015bd14bf17b712aa304c30821a181bff1f7b22d6323b067a232526720fd91ed8054730e714ad163220a11986213a1c2d1af22958207c"
//            + "2d3428922d710d33207a23831f430a792658042719762dd50b811f412cb20486315219ed084c1b221570327226b60e1907b224b215911ab3266128cf21c623f4"
//            + "08930e9230331dba23790b5c0fdb26530d97323712cd279612d40c7a14341fc323a32893131c2cf520412ca60c28059a09c8181b2303275e2c13119c22772d28"
//            + "1f5304941900134f07d2085b1dd9107b03ab0ce118d206be2eb32d3c0d981bcb0b1920f80b6c0e7b311118cc16542bb61f1005dc0fa9319b25d1165f234d0fdc"
//            + "08e41cc4035605ad04990a0a14142e81172228b31963098a20ac27b723e9161922432b4330ef102d1067316f239e107f071d11e4053b182817f715b72c3a1ab4"
//            + "1b0213a419c618060d9e0ba01be010820ed41e8e28580cd12bd81f7a1f4505be21862ac1262601b814ad10241476048d211c2d541834319909dd0ed11c4c29b8"
//            + "1ba22af20689271821210b22049c0e391f6e0a6406ae1a2d06f322f80db72973127719e70fbb17070f460f732999089523ae28dd1347263431831a932264294a"
//            + "0dc005b6211116c42daf232623ef12fa08040bc8183e1bec1d0510bd2c5f11aa20d60e5405672d46244b2b5b2c5e18740e37304c13b311ac2fb5266129600af1"
//            + "0edc0ccb1b5030bc1abf0c1913b425c0144711a922040f352d5a2c3610390db626142ea614430503062a252f030a20a22ec4308d14fd17be19b12bac06752f86"
//            + "237330d7132006e5229106e52a3b1d64081503c40fd230cd19ae0be3243b2c0b02601e0809421bff0ed72ede16b5201a0a9f27871c4832e023d82a40056f0584"
//            + "136204270dbf1b0103a627c00e9315ce02b004ac1e0e06e025b526cd0e60252231d706c01d5c32fb26fc31452d3a282b20a02c042eb721d10c1126d105702c27"
//            + "21ed246f18482f0e1cf802632ec20da91a501217277516850e0321ab0a3f06d80bb3241d0fee170b247d1be804700cdb28831720108f2e9924312f9a232f197f"
//            + "2aad15b91534092413621c6630f623280b36208014c92fe41d9306982d0d19141b0e053e09f915001fce27b90b521bf00502151114641c50066508f12a290bb4"
//            + "2cb908c22ef225262ddc121a0b3c2a9829f40b8719e616520b1b1c250a94160b19690a552bc22e452086266b315e14bc1240038c31f0098005d22e4e073711ef"
//            + "040d2df103f42555198d30d80eed31c71852035817a80788070c201f286017bc0f082a8b23412f9328f1166f147529e62c2f210e16be1ade0e821346103322f6"
//            + "222d1178119d299a1fd6272415b80d390fd4131a0e6712dd197305a40fd43157302725b315961b952b0513ff0278266c3015077120542d991b7808882b750f3a"
//            + "093906f61288181d269f10aa22782eb5280410d82dc132170e8d1ef71cb5068219491c7514db31420f7e2df627372e5713a8073d2817025d2b862b3004ac2f8f"
//            + "22e11c8f03cc259520d427fb100218a522121be202a22e0f29080f1b23e524941efa21a80d350f76317811d01c7d101b24e10c9e0bed1bbc21e821e31eb7044e"
//            + "2c80287609b123071daa0b93051b2dd205b515a325d92643087814fe1978286a02c03110301b31d121b6261002e91ecb275f090a2afb230612302fbf12f21d2a"
//            + "23771846087324ed14930694317703ac278a249e19af11350e3f05882a5d2b3f26d229f628da06cf06732f7317cc230c2bda037609f5186e2a2e29882b3d1757");
//
//    private static final byte[] SENDB = Hex.decode(
//        "8c06d4972b4521374d5ce3404823db20bd5b6288795faa324216a54e8cdcd20676ba83609f5db66a1967a6079f9126e512061cf9d58dea45e7814e22c9bc2ff3"
//            + "661546a65985f70da5fb10d675352211e847387c1b5dc0badd34284a552d7904680528d0dbb74e69ab90d844b149d81613a09c46fa6690b845707a6970953755"
//            + "10b2abfc4675a85e3b48908011e4b53bdce691ae64c7c48f35b8c7e02cd68a0eb745139ee560984d015d4d94252408a715f0e58306ad84532794a57a75859499"
//            + "14c4ad68b74189f0ac4d7c8947299a12d981cc2ff3581636b1515cd7b73d103def24321a05a489b8849bb3fa64b5ab690e2a57d4359621d56be79c1f396ed3e2"
//            + "63068c138e64a26be6851dd971a69fe07adea867f1323655ed934ce6ae103464cc2ba96ff038996b0bc9321e1fec6a9844c5389eb6897aa98755aebacbbf9379"
//            + "258b8311a4c44e7287edc6bd8765840eccc7c8b322e57131908ab33985b79b9c1c91077c8d41dedcbad2505459293dba42d0bf56d8f298ad216f7ad26fa817f6"
//            + "4f2e525604d4092f36014e0698660c804b28e1e03e98d391636516e11b7d8d4eb82b60bec3a3bbd4944068574159517028a5d06e721a187e0a9f294569964e96"
//            + "9a56cd371ea8556ea76151a75a4bce622d885f9892c92537ab63c17d43a79704988443980c2cd35ac69c916457e3b230087bcc92c34c607b7a633ae32c39bbbd"
//            + "ad4bf0f98a957e854078061991256da5cbc0d07d0a8a610b1be0063cc8271716866174c28810ad4d40d7d916bafb7a1c8253826569dd2e16d4c5f48baea82fd5"
//            + "d3412f9c680eaf0de8001c8c8766eb87fb81a771c67a269b155ee6a2e158719d205b0a8b7b89480e5c8ef7da18b8437f618c402ef11c5e8a6d59110962c94a4b"
//            + "83a4587b58152ba895deab6c52beb9572474de1cbda147b189cbd4f1c400f985505dcf8497f65408ade1677ab434ecdc19aad3ba558e83aa5200b5555e812d2b"
//            + "3320812b9e4fb47b20948c40269a115118b941be5926ad77c09b89a72f56be50c716e4016d384dda5fd0ab014847dccdd3044a94a8537e2b8e20043cc19be364"
//            + "128632016321456ab2f390e29a43e42155656d5b5fb96a9812f71323b88899279f9b4da45fc26a6c91f7dd868e4aa12abef11b21e59e6758fd9c8118fb4aaeed"
//            + "6700a8bcdad2228f9dd15593a3b1207d24f2a0d40034de9265f609acaa17e93cca96899f67811ffa9265786217d340f42a09316766d3fc8829a71d8ce7213433"
//            + "c6c515fbd8b9626bc1b67a0f6946de4b886792aa2f77030d08532eadfea21e80d902b9d24472e363a26a6dd8cee685b88517438949373e4a11a18002240e0341"
//            + "2c6057a230b7b51354891a86407ec612f8fdf538d08fd925812815c2d4a78ab2268e0f283e76dced3a410f396501643dbc494c55c9fd5c5ed08e28472100df58"
//            + "2da681fc71fa200e83d3a860d556c456614c93f5c69e013d6c53ee6fe9423b9d277d4da32b6681af7d9e890b8fb01700d679881e017edd142d32f3e5bee54050"
//            + "3372519abcc796b2d830042b0f7b97e639188b21c7231552053ed508b5ed851c0681d850230879a7c46f185a5a54b7dc1933c782434158fc43480d80d65714ab"
//            + "54452d5544987187c655a2a3f41bbe187988c1a0702ad03a8c530262141c75830a6e962bda4f208f7a7a6f4ead5995b985bd3c5a5029aa92f6f56405c2d08155"
//            + "6d860441e077e0053ae74061f9351e7927871b75625d0cb2433e205bb97030c5ccc9fffe9cedc62a683db90e396f2eb485305d62a76c782cbe66508bf5b130b2"
//            + "8c8da2c993865d667e22e789301a1a94506d995d6a11581f4f314e7cbfcc4c65e7d76e48062ecff6fa32af5ac58b00b738421b211ad9ad060a3b2b67903ad28e"
//            + "4b2214c3a14429a0d68369f856132b24e183c48991c28c35e6be2e83c1ccf078199189f55d835798008270cdbe409a5c9954c63e400e6d91694850e2352e8559"
//            + "c34f19f7fd4c429bcb0bba944d8c0c41706361b967c96ba1eaa266cea84cd37f0c6a40caafaae8d40a89d0ca06967ca910d6a20a29685dfc2be692b0f9b0ec96"
//            + "9723bc5996926bb2d806d86369a04dd7c272752467922128b2966b868b4559fe936baaf5c8b6892c916dab935381387da2e0f71cb26abf089913820a33b564a5"
//            + "2b625d810c570cd147d212e649f994a1a2a7ac2e30e310f1be5359cb892016123cd27dd4efd64227eb83a90e99a79fcbc9176be25c838eb6eabbee8bbb455259"
//            + "269197ac4c66ea383e5e265aeb1bf64c34ffd4779a6800ac4e12b1277a8c59b89f4c728cc93e71ec93c7bfd09a8e9cbf19bde439aa95a2a35c31ab4b4314d252"
//            + "b5702f1ed69573fe12315f3561efc22ddb4b98a747922b4944c79457e430e9adbe98dcc0231bdc88a58bf67c034da18584dc7c49c776892236b67c1762f3eb1d"
//            + "7f2323aebbf211b2b8074d29273847e50f8d43bcae33db20678a3ed61f7ac49ea6a3f0361cd0c1752c7a0a78ad52d8c9ae755b575dd28bf05b7b0ef438b85d89"
//            + "f9edd1f598c8e972211d971df25d64d9a29fecb4de3c828219434ade29509f6170142ac0756b7176658fa4f3f7e00f2cac901db5e0bc6c3d5c0028572ff0de3a"
//            + "f09cf1935e7c3231ad025570a895e9edbbe8d509df51a7297e729cf24e83c1e5237536417c96bc265addcf7b9f6e4dccfe45a4219b533d5db3c596cc2eed06ae"
//            + "de6f4a9d6935367e204127eeb4547c38d830e7e9e99cac5effef27b8f57dd07c2e60e4d79ab22e250829d347c5a80730ed957a83334b1a1470d08db01b9552dc"
//            + "092b1d3597c97f34332d4e1e503a3b755ade39b68a5ef9b9c13efd7cc4f47484dab6000750222510cfee516c5f23efdf70fd196fcf136a0bdb23745707a95a4a");
//
//    private static final byte[] KEYB = Hex.decode("5946400eed4b18ce8d7fb1f744e46e5689009aa4672526c0c59a0adb3dd3ca37");

    private static final int ROUNDS = 1000;

    private void testKeyExchange() throws Exception
    {
        SecureRandom aliceRand = new SecureRandom();
        SecureRandom bobRand = new SecureRandom();

        for (int i = 0; i < ROUNDS; ++i)
        {
            NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

            kpGen.init(new KeyGenerationParameters(aliceRand, 2048));

            AsymmetricCipherKeyPair aliceKp = kpGen.generateKeyPair();

            NHExchangePairGenerator exchGen = new NHExchangePairGenerator(bobRand);

            ExchangePair bobExchPair = exchGen.generateExchange(aliceKp.getPublic());

            NHAgreement agreement = new NHAgreement();

            agreement.init(aliceKp.getPrivate());

            byte[] aliceSharedKey = agreement.calculateAgreement(bobExchPair.getPublicKey());

            isTrue("value mismatch", Arrays.areEqual(aliceSharedKey, bobExchPair.getSharedValue()));
        }
    }

    private void testPrivInfoGeneration()
        throws IOException
    {
        SecureRandom random = new SecureRandom();
        NHOtherInfoGenerator.PartyU partyU = new NHOtherInfoGenerator.PartyU(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partA = partyU.getSuppPrivInfoPartA();

        NHOtherInfoGenerator.PartyV partyV = new NHOtherInfoGenerator.PartyV(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partB = partyV.getSuppPrivInfoPartB(partA);

        DEROtherInfo otherInfoU = partyU.generate(partB);

        DEROtherInfo otherInfoV = partyV.generate();

        areEqual(otherInfoU.getEncoded(), otherInfoV.getEncoded());
    }

    private void testReuse()
        throws IOException
    {
        SecureRandom random = new SecureRandom();
        NHOtherInfoGenerator.PartyU partyU = new NHOtherInfoGenerator.PartyU(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partA = partyU.getSuppPrivInfoPartA();

        NHOtherInfoGenerator.PartyV partyV = new NHOtherInfoGenerator.PartyV(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partB = partyV.getSuppPrivInfoPartB(partA);

        DEROtherInfo otherInfoU = partyU.generate(partB);

        DEROtherInfo otherInfoV = partyV.generate();

        areEqual(otherInfoU.getEncoded(), otherInfoV.getEncoded());

        try
        {
            partyV.generate();
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("builder already used", e.getMessage());
        }

        try
        {
            partyU.generate(partB);
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("builder already used", e.getMessage());
        }
    }

    private void testInterop()
    {
        /*
         * Test interoperability with the C reference implementation as of:
         *
         *     https://github.com/tpoeppelmann/newhope/commit/bc06c1ac04101449797ae8d1029e73cdcd82f79f
         *
         * (version corresponding to the newhope-20160328.pdf paper).
         * 
         * Note that 'SENDB' and 'KEYB' were both generated by the C implementation upon receipt of a
         * 'SENDA' (not kept) generated together with 'SECRETA'.
         */

        // NOTE: This passes as of writing, but requires public access to NewHope (currently package scope)
        /*
        short[] secretA = new short[SECRETA.length / 2];
        for (int i = 0; i < secretA.length; ++i)
        {
            secretA[i] = Pack.bigEndianToShort(SECRETA, 2 * i);
        }

        byte[] keyA = new byte[NewHope.AGREEMENT_SIZE];
        NewHope.sharedA(keyA, secretA, SENDB);

        isTrue("value mismatch", Arrays.areEqual(keyA, KEYB));
        */
    }

    public String getName()
    {
        return "NewHope";
    }

    public void performTest()
        throws Exception
    {
        testKeyExchange();
        testInterop();
        testPrivInfoGeneration();
        testReuse();
    }

    public static void main(
            String[]    args)
    {
        runTest(new NewHopeTest());
    }
}
