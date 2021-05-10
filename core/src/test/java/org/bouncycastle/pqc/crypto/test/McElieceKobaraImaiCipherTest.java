package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKobaraImaiCipher;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class McElieceKobaraImaiCipherTest
    extends SimpleTest
{

    SecureRandom keyRandom = new SecureRandom();

    public String getName()
    {
        return "McElieceKobaraImai";

    }

    private void checkEncoding()
        throws Exception
    {
        checkEncoding(new McElieceCCA2Parameters("SHA-1"));
        checkEncoding(new McElieceCCA2Parameters("SHA-224"));
        checkEncoding(new McElieceCCA2Parameters("SHA-256"));
        checkEncoding(new McElieceCCA2Parameters("SHA-384"));
        checkEncoding(new McElieceCCA2Parameters("SHA-512"));
    }

    private void checkEncoding(McElieceCCA2Parameters params)
        throws Exception
    {
        McElieceCCA2KeyPairGenerator mcElieceCCA2KeyGen = new McElieceCCA2KeyPairGenerator();
        McElieceCCA2KeyGenerationParameters genParam = new McElieceCCA2KeyGenerationParameters(keyRandom, params);

        mcElieceCCA2KeyGen.init(genParam);
        AsymmetricCipherKeyPair pair = mcElieceCCA2KeyGen.generateKeyPair();

        McElieceCCA2PrivateKeyParameters priv1 = (McElieceCCA2PrivateKeyParameters)pair.getPrivate();
        McElieceCCA2PublicKeyParameters pub1 = (McElieceCCA2PublicKeyParameters)pair.getPublic();

        McElieceCCA2PrivateKeyParameters priv2 = (McElieceCCA2PrivateKeyParameters)PrivateKeyFactory.createKey(PrivateKeyInfoFactory.createPrivateKeyInfo(priv1));
        McElieceCCA2PublicKeyParameters pub2 = (McElieceCCA2PublicKeyParameters)PublicKeyFactory.createKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub1));

        isEquals(PrivateKeyInfoFactory.createPrivateKeyInfo(priv1), PrivateKeyInfoFactory.createPrivateKeyInfo(priv2));
        isEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub1), SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub2));

        byte[] msg = Arrays.concatenate(Strings.toByteArray("A not so random string"), new byte[155]);

        McElieceKobaraImaiCipher cipher = new McElieceKobaraImaiCipher();
        cipher.init(true, pub1);
        byte[] enc1 = cipher.messageEncrypt(msg);

        cipher.init(false, priv2);
        byte[] dec1 = cipher.messageDecrypt(enc1);
  
        isTrue(Arrays.areEqual(msg, dec1));

        cipher.init(true, pub2);
        byte[] enc2 = cipher.messageEncrypt(msg);

        cipher.init(false, priv1);
        byte[] dec2 = cipher.messageDecrypt(enc2);

        isTrue(Arrays.areEqual(msg, dec2));
    }

    public void performTest()
        throws Exception
    {
        checkEncoding();

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
