package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors from the NIST standard tests and Brian Gladman's vector set
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">
 * http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 */
public class RijndaelTest
    extends CipherTest
{
    static SimpleTest[]  tests = 
            {
                new BlockCipherVectorTest(0, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(1, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
                new BlockCipherMonteCarloTest(2, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
                new BlockCipherMonteCarloTest(3, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
                new BlockCipherVectorTest(4, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
                new BlockCipherMonteCarloTest(5, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
                new BlockCipherVectorTest(6, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
                new BlockCipherMonteCarloTest(7, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
                new BlockCipherVectorTest(8, new RijndaelEngine(160),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c")),
                        "3243f6a8885a308d313198a2e03707344a409382", "16e73aec921314c29df905432bc8968ab64b1f51"),
                new BlockCipherVectorTest(8, new RijndaelEngine(160),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160")),
                        "3243f6a8885a308d313198a2e03707344a409382", "0553eb691670dd8a5a5b5addf1aa7450f7a0e587"),
                new BlockCipherVectorTest(8, new RijndaelEngine(160),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5")),
                        "3243f6a8885a308d313198a2e03707344a409382", "73cd6f3423036790463aa9e19cfcde894ea16623"),
                new BlockCipherVectorTest(8, new RijndaelEngine(160),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90")),
                        "3243f6a8885a308d313198a2e03707344a409382", "601b5dcd1cf4ece954c740445340bf0afdc048df"),
                new BlockCipherVectorTest(8, new RijndaelEngine(160),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe")),
                        "3243f6a8885a308d313198a2e03707344a409382", "579e930b36c1529aa3e86628bacfe146942882cf"),
                new BlockCipherVectorTest(8, new RijndaelEngine(192),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d", "b24d275489e82bb8f7375e0d5fcdb1f481757c538b65148a"),
                new BlockCipherVectorTest(9, new RijndaelEngine(192),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d", "725ae43b5f3161de806a7c93e0bca93c967ec1ae1b71e1cf"),
                new BlockCipherVectorTest(10, new RijndaelEngine(192),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d", "bbfc14180afbf6a36382a061843f0b63e769acdc98769130"),
                new BlockCipherVectorTest(11, new RijndaelEngine(192),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d", "0ebacf199e3315c2e34b24fcc7c46ef4388aa475d66c194c"),
                new BlockCipherVectorTest(12, new RijndaelEngine(224),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9", "b0a8f78f6b3c66213f792ffd2a61631f79331407a5e5c8d3793aceb1"),
                new BlockCipherVectorTest(13, new RijndaelEngine(224),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9", "08b99944edfce33a2acb131183ab0168446b2d15e958480010f545e3"),
                new BlockCipherVectorTest(14, new RijndaelEngine(224),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9", "be4c597d8f7efe22a2f7e5b1938e2564d452a5bfe72399c7af1101e2"),
                new BlockCipherVectorTest(15, new RijndaelEngine(224),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9", "ef529598ecbce297811b49bbed2c33bbe1241d6e1a833dbe119569e8"),
                new BlockCipherVectorTest(16, new RijndaelEngine(224),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa9", "02fafc200176ed05deb8edb82a3555b0b10d47a388dfd59cab2f6c11"),
                new BlockCipherVectorTest(17, new RijndaelEngine(256),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8", "7d15479076b69a46ffb3b3beae97ad8313f622f67fedb487de9f06b9ed9c8f19"),
                new BlockCipherVectorTest(18, new RijndaelEngine(256),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8", "514f93fb296b5ad16aa7df8b577abcbd484decacccc7fb1f18dc567309ceeffd"),
                new BlockCipherVectorTest(19, new RijndaelEngine(256),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8", "5d7101727bb25781bf6715b0e6955282b9610e23a43c2eb062699f0ebf5887b2"),
                new BlockCipherVectorTest(20, new RijndaelEngine(256),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d90")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8", "d56c5a63627432579e1dd308b2c8f157b40a4bfb56fea1377b25d3ed3d6dbf80"),
                new BlockCipherVectorTest(21, new RijndaelEngine(256),
                        new KeyParameter(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe")),
                        "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8", "a49406115dfb30a40418aafa4869b7c6a886ff31602a7dd19c889dc64f7e4e7a")
            };

    RijndaelTest()
    {
        super(tests, new RijndaelEngine(128), new KeyParameter(new byte[16]));
    }

    public String getName()
    {
        return "Rijndael";
    }

    public static void main(
        String[]    args)
    {
        runTest(new RijndaelTest());
    }
}
