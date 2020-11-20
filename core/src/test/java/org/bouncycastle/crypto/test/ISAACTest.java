package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.ISAACEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * ISAAC Test - see https://www.burtleburtle.net/bob/rand/isaacafa.html
 */
public class ISAACTest
    extends SimpleTest
{
    byte[] out = Hex.decode(
        "f650e4c8e448e96d98db2fb4f5fad54f433f1afbedec154ad837048746ca4f9a" +
        "5de3743e88381097f1d444eb823cedb66a83e1e04a5f6355c744243325890e2e" +
        "7452e31957161df638a824f3002ed71329f5544951c08d83d78cb99ea0cc74f3" +
        "8f651659cbc8b7c2f5f71c6912ad6419e5792e1b860536b809b3ce98d45d6d81" +
        "f3b2612917e38f8529cf72ce349947b0c998f9ffb5e13dae32ae2a2bf7cf814c" +
        "8ebfa303cf22e0640b923200eca4d58aef53cec4d0f7b37d9c411a2affdf8a80" +
        "b40e27bcb4d2f97644b89b08f37c71d51a70e7e90bdb9c3060dc5207b3c3f24b" +
        "d7386806229749b54e232cd091dabc65a70e11018b87437e5781414fcdbc62e2" +
        "8107c9ff69d2e4ae3b18e752b143b6886f4e077295138769943c3c74afc17a97" +
        "0fd439636a529b0bd8c58a6aa8bcc22d2db35dfea7a2f4026cb167db538e1f4e" +
        "7275e2771d3b8e97ecc5dc9115e3a5b90369661430ab93ecac9fe69d7bc76811" +
        "60eda8da28833522d5295ebc5adb60e7f7e1cdd097166d14b67ec13a210f3925" +
        "64af0fef0d0286843aea3decb058bafbb8b0ccfcf2b5cc05e3a662d9814bc24c" +
        "2364a1aa37c0ed052b36505c451e7ec85d2a542fe43d0fbb91c8d92560d4d5f8" +
        "12a0594b9e8a51dacd49ebdb1b0dcdc1cd57c7f7e63444517ded386f2f36fa86" +
        "a6d1210133bc405db388d96cdb6dbe96fe29661c13edc0cbcb0eee4a70cc94ae" +
        "de11ed340606cf9f3a6ce38923d74f4ea37f63ff917bdec2d73f72d40e7e0e67" +
        "3d77d9a213add9228891b3db01a9bd7056a001e3d51f093dcc033ce35ad0d3b0" +
        "34105a8c6a123f57bd2e50247364944be89b1a3b21835c4d9f39e2d9d405ded8" +
        "294d37e5bccaaeed35a124b56708a2bcb00960ba2a98121a4d8fae820bb3263f" +
        "12595a196a1075890809e49421c171ec884d682514c8009bb0b84e7b03fb88f4" +
        "28e7cb789388b13bdd2dc1d5848f520a07c28cd168a3935872c9137d127dd430" +
        "c613f1578c2f0d55f7d3f39f309bfb788406b13746c0a6f53718d59708607f04" +
        "76904b6d04db4e13cd7411a7b510ce0ebfc7f7ccb83f957afdfef62dc35e4580" +
        "3ff1e5244112d96c02c9b944d5990dfbe7e265810d9c7e7e826dfa8966f1e0ab" +
        "30bcc764eadebeaced35e5ee0c571a7de4f3a26af7f58f7badf6bc235d023e65" +
        "1ed3ff4eec46b0b6d2a93b51e75b41c97e315aeb61119a5a53245b7933f6d7b1" +
        "cae8deba50fc8194afa92a6dc87c80064188bfcd8bace62e78ffa5685597ec0f" +
        "b4415f7d08294766ad56764309c36f903dde9f394a0a283c18080c8e080c79ec" +
        "79ae4c10cb9e15637cdd662f62d31911a4ca0cf15cf824cd3b708f991e16614c" +
        "b6b9d7665de87abb7229ea81d5b2d75056e6cd21fe1e42d596da2655c2b9aa36" +
        "b8f6fd4a6a158d1001913fd3af7d1fb80b5e435f90c107576554abda7a68710f" +
        "82ac484fd7e1c7be95c85eaa94a302f44d3cfbda786b29081010b27582d53d12" +
        "21e2a51c3d1e9150b059261dd0638e1a31860f0581f2864dff4cfc350451516d" +
        "bd086f26bc5654c165dfa427a82427f5582e3014b8d2486dc79a17499a1d7745" +
        "8766bb541e04a7f73d3dff8ad5ec6bf4dbef7d9f36ec0ea31feb2e4f15cfcc5c" +
        "d8c423fbd0ef3cc9eb244925ba5590c8a5f48ac433c5321c613b67b2479c3a22" +
        "e21339cc10d210aa931dd7e2ef05ee06b82f2703a385cb2c5d67133c877eb7b4" +
        "1e3437f75afb43ae53c078f394d904811d96458908063a85e13222281956b1e5" +
        "31860f132e7b022f21182ca396f703ac46819e2e0d28fe523724d4dca0eabe6b" +
        "c66699fdc6112fdd19c1e69c04d3658a4b55dd9931907d62f854b5224d678f26" +
        "22ae0582eafed133e4a51d2184bd6dd6c1a513753f28ee63fb737b1a70a1660e" +
        "8a8dfaa31be79937f7476978513c1764531ac6bf12c06908001cdb951a4b6a53" +
        "d067fce512b2cfb69ddb477f740e006639ddf25acc8bfa2df1b20eaf64f2632c" +
        "9783cdee63bfd4d80084cfe575f4e9e219b48fd06c48ddd87a36af9371865c4c" +
        "9ce0199d867027d72cb7b77f84ef01da72f5972f040f7074df9afa29c921f94e" +
        "75c08a3618c1ef9ad649a428c5b719378a30738ad97cd348858129a6239e3b0a" +
        "bbb8abc480fac4c2ecfcf20bd9d711f9e2a4ef71b5fe87c0be8b06b2aafef5a7" +
        "9c15db3b0aeb81654389a84a253b1d7a19047c797cdc78a2d20adf0356f55a71" +
        "3e730fa8fd8650d8959e234eb7546681dad1b22a142a6e858ef4bce668235b9d" +
        "85a13f8574096ae7a949bea229322d0dd568385882846526403dae086dd1943a" +
        "e1279bff9e7e4f041c3a4524484525e481d4cc5fe24124c0037464c0bf1bd691" +
        "26ceb003275ead3ac5bde90826414ff3a30519add7b43abe2ce5d3d588412761" +
        "97ca2070e5fbb9c7276df0b4308f751f37a97df6c9cd808cfe4cb3803d469303" +
        "aee19096c0d5d42a4e823ad3f5f9cc3b4286619c9ca45e1c66c97340891aec49" +
        "45bae606c798f04752649d6cce86fdfc80c6e402d6ec2f2b27c822821fe26ce0" +
        "92f57ea7de462f4d07497cae5a48755c721502dd6cbe7935836d80039ead7f70" +
        "9ab3a42f4c8652d632e39273e8fa38601da4f25a0cd6ef8102503f7d8854a0a1" +
        "9a30c4e88815715305efe29457c4c9252887d96fc1a71e3ce9f841632d0985de" +
        "d21e796c6fb5ce5602614abfc3c7be2cb54fed6fa617a083c3142d8f6079e4ce" +
        "ceffc1471d0cb81bdc153e5fe36ef5bbd531161a165b10157aa114ed3f7579b3" +
        "f7f395f1bc6172c7a86f875e0e6c51b3cdfec2af73c0e762824c2009c5a87748" +
        "94d401258aba3ffbd32be0608c17eff021e2547e07cffad905340e15f3310c92" +
        "9d8d190886ba527ff943f672ef73fbf046d95ca5c54cd95b9d855e894bb5af29");

        byte[] outFFFFFFFF = Hex.decode(
            "de3b3f3c19e0629c1fc8b7836695d523e7804edd86ff7ce9b106f52caebae9d9" +
            "72f845d49ce17d7da44e49bae954aac0d0b1284b98a88eec1524fb6bc91a16b5" +
            "1192ac5334131446ac2442de9ff3d5867b9b9148881ee30a6e87dd88e5d1f7cd" +
            "98db31ff36f70d9850cfefaef42abb00ecc39ed308bf4b8030cdc2b6b7e42f0e" +
            "908030dd282f96edacc888b3a986e109c129998f89baa1b5da8970b07a6ab012" +
            "f10264f23c315c9c8e0c164955c68517b6a4f982b2626db70787f869ac6d551b" +
            "e34931627c7058e965c502e18d2cd370e6db3b70d947d61aa9717cf8394f48c6" +
            "3c796f3a154950846badb28b70d982f29bc670254e3e5e0f8e36b0a5f6da0a04" +
            "6b235ed6a42988c012bde74d879fa8eb5d59f5f40ed5e76601c9847b3edb2690");

        byte[] outFFFF0000 = Hex.decode(
            "26c54b1f8c4e3fc582e9e8180f7aba5380463dcf58b03cbeda0ecc8ba90ccff8" +
            "5bd50896313d7efed44015faeac6964b241a7fb8a2e37127a7cbea0fd7c020f2" +
            "406371b87ef5185089504751e5e44352eff63e00e5c28f5dff0616a9a3a00f1f" +
            "4a1350e3a17be9abddfc2c94571450a0dc4c3c0c7c7f98e80c95f607d50c676a" +
            "9a3006f9d279a79a4d66b2ab0c52930c9ee84bc09895e70fa041b1a3a2966f11" +
            "6a47fd09705124b1f5c7ae055e54536e66584b1608f3612d81b72f109a385831" +
            "121945b207b90ac72437a248f27a121c2801f4153a8699fb047e193f7ba69e1b" +
            "b117869675d4c963e6070c2ca3d332ce830cb5e3d9ed2eee7faf0acc20fbe154" +
            "188ae789e95bd5c1f459dbd150aab6eb833170257084bc5d44e9df09f5624f9d" +
            "afecd0c9340ac8587f8625d343f7efd1cc8abcf7a6f90eabd4e8e2d906278d6e" +
            "431fcade165c8c467887fbf5c26d341557b064b98c60dd40ab262dc046d69647" +
            "56f3ddc1a07ae5f87be878b9334fcde40add68d2ca1dc05fb1670f998c7c4607" +
            "9a6e48bdb330ad8d30b61b5cc8dc156f5733905931949783f89ac396b65aa4b8" +
            "51f746b53ed8ea66130e1d75e8eab136e60450e3e600226bc8e17d03744ce94c" +
            "0eec9234fea5f18eef65d81f2f10cfbc0b112b8cde17c32eb33ed81d7356eac3" +
            "eb1cb9cefa6604c2d707949b6e5a83e60705bf6aae76dcc7d35d68ff149c1ac5" +
            "424bb4a39e2f496f886637fce3db4ba4ad12c1a32d25e1606f6635ff636486f6" +
            "714997b45477f38813c02afce4bebf196b813332f0decd567c745f441e736364");

       byte[] out0000FFFF = Hex.decode(
        "bc31712f2a2f467a5abc737c57ce0f8d49d2f775eb850fc8f856daf19310fee2"+
        "5bab40e78403c9ef4ccd971418992faf4e85ca643fa6b482f30c4659066158a6"+
        "5bc3e620ba7ea5c34dd0eac5aabb2cf078d915fd1f8c437ed00423076c10f701"+
        "eefa7fc7c461aca5db8a87be29d925c4212d4adcfa71ff5b06af15c048aa0dfd"+
        "f0e645bc09fea200c430a88eb38c466ff358b836f1159656a078f6fc752f6db1"+
        "6680bb30fc771a6a785bbb2298e947d7b3500e557775962248bedf4e82c16e66"+
        "f39283ccb95e5399061056a11c4a280f00f7487888199487905273c7aa13012b"+
        "4849eca626cbf071c782e084f9fded57de92313e5f61a6e81117fb1115eff275"+
        "66fd5c755bb3b01bba69aeb8f1b1b1cc9709734be31b35bc707d372ba6fe70d1"+
        "e2c3b0e5e74a7058faff6b11d3a168f19fecc9fcb36b3e6a5f828c01c22ac0c2"+
        "5da2a3a9eec7e0ebbbf51472e430ed4cf1c7ab57ef9aea511e40250846d260b6"+
        "17a3fdeba16cf4afaf700144d3296b58b22a3c79ed96f3e2fc8d9e3c660ae153"+
        "8e0c285ccdc48b59117e80413bd0ad24c6a8d4f133fe1496f14351bb89904fa5"+
        "e10c4b8d50e0604578389c336a9ab3d292beb90ce640fc028e697cf54e021e2f"+
        "c0ca3fe0471fde5e5462f221739a74f5a13ae0621fe2a82e752bc294f63de48d"+
        "e85430af71307a30441b861ab5380e6a6dbe1251c9baa567da14e38e5a0ccddf"+
        "0127205c38fc3b77065e98101d219246103438d223ec7f8f533d4bb3a3d3407a"+
        "944910f11e8e5492e86de7a0471250eca32f0838b3db02fffe71898712af3261");

    public String getName()
    {
        return "ISAAC";
    }

    public void performTest()
    {
        ISAACEngine engine = new ISAACEngine();

        doTest(engine, Hex.decode("00000000"), out);
        doTest(engine, Hex.decode("ffffffff"), outFFFFFFFF);

        byte[] k = new byte[256 * 4];
        for (int i = 0; i != k.length; i++)
        {
            k[i] = (byte)((i % 4 == 0 || i % 4 == 1) ? 0xff : 0x00);
        }
        doTest(engine, k, outFFFF0000);
        k = new byte[256 * 4];
        for (int i = 0; i != k.length; i++)
        {
            k[i] = (byte)((i % 4 == 2 || i % 4 == 3) ? 0xff : 0x00);
        }
        doTest(engine, k, out0000FFFF);
    }

    private void doTest(ISAACEngine engine, byte[] key, byte[] output)
    {
        byte[] in = new byte[output.length];
        byte[] enc = new byte[output.length];
        engine.init(true, new KeyParameter(key));
        engine.processBytes(in, 0, in.length, enc, 0);
        if (!areEqual(enc, output))
        {
            fail("ciphertext mismatch");
        }
        engine.init(false, new KeyParameter(key));
        engine.processBytes(enc, 0, enc.length, enc, 0);
        if (!areEqual(enc, in))
        {
            fail("plaintext mismatch");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new ISAACTest());
    }
}
