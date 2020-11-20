package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * SEED tester - vectors https://www.ietf.org/rfc/rfc4009.txt
 */
public class SEEDTest
    extends CipherTest
{
    static SimpleTest[]  tests =
    {
        new BlockCipherVectorTest(0, new SEEDEngine(),
            new KeyParameter(Hex.decode("00000000000000000000000000000000")),
            "000102030405060708090a0b0c0d0e0f",
            "5EBAC6E0054E166819AFF1CC6D346CDB"),
        new BlockCipherVectorTest(0, new SEEDEngine(),
            new KeyParameter(Hex.decode("000102030405060708090a0b0c0d0e0f")),
            "00000000000000000000000000000000",
            "c11f22f20140505084483597e4370f43"),
        new BlockCipherVectorTest(0, new SEEDEngine(),
            new KeyParameter(Hex.decode("4706480851E61BE85D74BFB3FD956185")),
            "83A2F8A288641FB9A4E9A5CC2F131C7D",
            "EE54D13EBCAE706D226BC3142CD40D4A"),
        new BlockCipherVectorTest(0, new SEEDEngine(),
            new KeyParameter(Hex.decode("28DBC3BC49FFD87DCFA509B11D422BE7")),
            "B41E6BE2EBA84A148E2EED84593C5EC7",
            "9B9B7BFCD1813CB95D0B3618F40F5122"),
        new BlockCipherVectorTest(0, new SEEDEngine(),
            new KeyParameter(Hex.decode("0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E")),
            "0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E",
            "8296F2F1B007AB9D533FDEE35A9AD850"),
    };

    SEEDTest()
    {
        super(tests, new SEEDEngine(), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "SEED";
    }

    public static void main(
        String[]    args)
    {
        runTest(new SEEDTest());
    }
}
