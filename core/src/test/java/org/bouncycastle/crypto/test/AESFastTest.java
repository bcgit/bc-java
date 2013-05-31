package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors from the NIST standard tests and Brian Gladman's vector set
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">
 * http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 */
public class AESFastTest
    extends CipherTest
{
    static SimpleTest[]  tests = 
            {
                new BlockCipherVectorTest(0, new AESFastEngine(),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(1, new AESFastEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
                new BlockCipherMonteCarloTest(2, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
                new BlockCipherMonteCarloTest(3, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
                new BlockCipherVectorTest(4, new AESFastEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
                new BlockCipherMonteCarloTest(5, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
                new BlockCipherVectorTest(6, new AESFastEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
                new BlockCipherMonteCarloTest(7, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
                new BlockCipherVectorTest(8, new AESFastEngine(),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(9, new AESFastEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
                new BlockCipherMonteCarloTest(10, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
                new BlockCipherMonteCarloTest(11, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
                new BlockCipherVectorTest(12, new AESFastEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
                new BlockCipherMonteCarloTest(13, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
                new BlockCipherVectorTest(14, new AESFastEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
                new BlockCipherMonteCarloTest(15, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
                new BlockCipherVectorTest(16, new AESFastEngine(),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(17, new AESFastEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
                new BlockCipherMonteCarloTest(18, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
                new BlockCipherMonteCarloTest(19, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
                new BlockCipherVectorTest(20, new AESFastEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
                new BlockCipherMonteCarloTest(21, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
                new BlockCipherVectorTest(22, new AESFastEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
                new BlockCipherMonteCarloTest(23, 10000, new AESFastEngine(),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168")
            };
    
    private BlockCipher _engine = new AESFastEngine();

    AESFastTest()
    {
        super(tests, new AESFastEngine(), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "AESFast";
    }

    public void performTest()
        throws Exception
    {
        super.performTest();

        byte[] keyBytes = new byte[16];
        
        _engine.init(true, new KeyParameter(keyBytes));
        
        //
        // init tests
        //
        try
        {
            byte[]      dudKey = new byte[6];
            
            _engine.init(true, new KeyParameter(dudKey));
            
            fail("failed key length check");
        }
        catch (IllegalArgumentException e)
        {
            // expected 
        }
        
        try
        {
            byte[]      iv = new byte[16];

            _engine.init(true, new ParametersWithIV(null, iv));
            
            fail("failed parameter check");
        }
        catch (IllegalArgumentException e)
        {
            // expected 
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new AESFastTest());
    }
}
