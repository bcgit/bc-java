package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKobaraImaiCipher;
import org.bouncycastle.util.test.SimpleTest;

public class McElieceKobaraImaiCipherTest
    extends SimpleTest
{

    SecureRandom keyRandom = new SecureRandom();

    public String getName()
    {
        return "McElieceKobaraImai";

    }


    public void performTest()
        throws Exception
    {
        int numPassesKPG = 0;   // TODO: this algorithm is broken
        int numPassesEncDec = 10;
        Random rand = new Random();
        byte[] mBytes;
        for (int j = 0; j < numPassesKPG; j++)
        {

            McElieceCCA2Parameters params = new McElieceCCA2Parameters("SHA-256");
            McElieceCCA2KeyPairGenerator mcElieceCCA2KeyGen = new McElieceCCA2KeyPairGenerator();
            McElieceCCA2KeyGenerationParameters genParam = new McElieceCCA2KeyGenerationParameters(keyRandom, params);

            mcElieceCCA2KeyGen.init(genParam);
            AsymmetricCipherKeyPair pair = mcElieceCCA2KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);
            Digest msgDigest = new SHA256Digest();
            McElieceKobaraImaiCipher mcElieceKobaraImaiDigestCipher = new McElieceKobaraImaiCipher();


            for (int k = 1; k <= numPassesEncDec; k++)
            {
                System.out.println("############### test: " + k);
                // initialize for encryption
                mcElieceKobaraImaiDigestCipher.init(true, param);

                // generate random message
                int mLength = (rand.nextInt() & 0x1f) + 1;
                mBytes = new byte[mLength];
                rand.nextBytes(mBytes);

                msgDigest.update(mBytes, 0, mBytes.length);
                byte[] hash = new byte[msgDigest.getDigestSize()];
                msgDigest.doFinal(hash, 0);

                // encrypt
                byte[] enc = mcElieceKobaraImaiDigestCipher.messageEncrypt(hash);

                // initialize for decryption
                mcElieceKobaraImaiDigestCipher.init(false, pair.getPrivate());
                byte[] constructedmessage = mcElieceKobaraImaiDigestCipher.messageDecrypt(enc);

                // XXX write in McElieceFujisakiDigestCipher?

                boolean verified = true;
                for (int i = 0; i < hash.length; i++)
                {
                    verified = verified && hash[i] == constructedmessage[i];
                }

                if (!verified)
                {
                    fail("en/decryption fails");
                }
                else
                {
                    System.out.println("test okay");
                    System.out.println();
                }

            }
        }

    }

    public static void main(
        String[] args)
    {
        runTest(new McElieceKobaraImaiCipherTest());
    }

}
