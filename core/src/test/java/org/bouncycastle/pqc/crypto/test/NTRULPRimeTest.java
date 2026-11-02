package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class NTRULPRimeTest
    extends TestCase
{
    private static final String resourcePath = "pqc/crypto/ntruprime/ntrulpr";

    public void testKEM()
            throws Exception
    {
        NTRULPRimeParameters[] paramList = new NTRULPRimeParameters[]
        {
                NTRULPRimeParameters.ntrulpr653,
                NTRULPRimeParameters.ntrulpr761,
                NTRULPRimeParameters.ntrulpr857,
                NTRULPRimeParameters.ntrulpr953,
                NTRULPRimeParameters.ntrulpr1013,
                NTRULPRimeParameters.ntrulpr1277
        };

        for (int i = 0; i != paramList.length; i++)
        {
            NTRULPRimeParameters paramSpec = paramList[i];
            // System.out.println("****    Parameter Spec - '" + paramSpec.getName().toUpperCase() + "'    ****");
            InputStream resource = TestResourceFinder.findTestResource(resourcePath, Strings.toLowerCase(paramSpec.getName()) + ".rsp");
            BufferedReader resourceReader = new BufferedReader(new InputStreamReader(resource));

            String line;
            TestSampler sampler = new TestSampler();
            while ((line = resourceReader.readLine()) != null)
            {
                if (! line.startsWith("count"))
                    continue;
                int count = Integer.parseInt(line.split("=")[1].trim());
                line = resourceReader.readLine();
                byte[] seed = Hex.decode(line.split("=")[1].trim());
                line = resourceReader.readLine();
                byte[] pk = Hex.decode(line.split("=")[1].trim());
                line = resourceReader.readLine();
                byte[] sk = Hex.decode(line.split("=")[1].trim());
                line = resourceReader.readLine();
                byte[] ct = Hex.decode(line.split("=")[1].trim());
                line = resourceReader.readLine();
                byte[] ss = Hex.decode(line.split("=")[1].trim());

                if (sampler.skipTest(count))
                {
                    continue;
                }

                // System.out.println("Running Test-" + count + " ...");
                SecureRandom random = new ReferenceDrawsRandom(new NISTSecureRandom(seed, null), 4 * paramSpec.getP());
                NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
                keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(random, paramSpec));

                AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
                assertTrue(Arrays.areEqual(pk, ((NTRULPRimePublicKeyParameters)keyPair.getPublic()).getEncoded()));
                // System.out.println("- Public Key matched ...");
                assertTrue(Arrays.areEqual(sk, ((NTRULPRimePrivateKeyParameters)keyPair.getPrivate()).getEncoded()));
                // System.out.println("- Private Key matched ...");

                NTRULPRimeKEMGenerator kemGenerator = new NTRULPRimeKEMGenerator(random);
                SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(keyPair.getPublic());

                assertTrue(Arrays.areEqual(ct, secretEncapsulation.getEncapsulation()));
                // System.out.println("- Encapsulation Cipher Text matched ...");
                byte[] secret = secretEncapsulation.getSecret();
                assertTrue(Arrays.areEqual(ss, 0, secret.length, secret, 0, secret.length));
                // System.out.println("- Encapsulation Shared Secret matched ...");

                NTRULPRimeKEMExtractor kemExtractor = new NTRULPRimeKEMExtractor((NTRULPRimePrivateKeyParameters)keyPair.getPrivate());
                byte[] decryptedSecret = kemExtractor.extractSecret(ct);

                assertTrue(Arrays.areEqual(secret, decryptedSecret));
                // System.out.println("- Decapsulation Shared Secret matched ...");
            }

            resource.close();
        }
    }

    /**
     * A ciphertext changed anywhere decapsulates, by implicit rejection, to the secret the reference derives from rho
     * and the received ciphertext, SHA-512(0 | rho | ciphertext)[0:32], rather than the encapsulated one.
     * <p>
     * The secret used to be derived with prefix 1, as for a valid ciphertext, and from the re-encrypted ciphertext,
     * which depends only on the decrypted r, so ciphertexts that decrypt to the same r - such as two that differ only
     * in the confirmation hash - shared a rejection secret, telling an attacker so.
     */
    public void testImplicitRejection()
    {
        SecureRandom random = new SecureRandom();
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(random, NTRULPRimeParameters.ntrulpr761));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        NTRULPRimePrivateKeyParameters privateKey = (NTRULPRimePrivateKeyParameters)keyPair.getPrivate();

        SecretWithEncapsulation secretEncapsulation = new NTRULPRimeKEMGenerator(random).generateEncapsulated(
            keyPair.getPublic());
        byte[] secret = secretEncapsulation.getSecret();
        byte[] ct = secretEncapsulation.getEncapsulation();

        NTRULPRimeKEMExtractor kemExtractor = new NTRULPRimeKEMExtractor(privateKey);
        byte[] rho = privateKey.getRho();

        // the first byte, the last bytes of the rounded polynomial and of T, and the confirmation hash (twice)
        int[] positions = { 0, ct.length - 161, ct.length - 33, ct.length - 1, ct.length - 1 };
        byte[][] rejected = new byte[positions.length][];
        for (int k = 0; k != positions.length; k++)
        {
            byte[] tampered = Arrays.clone(ct);
            tampered[positions[k]] ^= (byte)(0x80 >>> k);

            rejected[k] = kemExtractor.extractSecret(tampered);
            assertFalse(Arrays.areEqual(secret, rejected[k]));
            assertTrue(Arrays.areEqual(Arrays.copyOfRange(hashWithPrefix(0, rho, tampered), 0, 32), rejected[k]));
        }

        // a changed confirmation hash decrypts to the same r, so re-encrypts to ct: not what the secret depends on
        assertFalse(Arrays.areEqual(Arrays.copyOfRange(hashWithPrefix(1, rho, ct), 0, 32), rejected[3]));
        assertFalse(Arrays.areEqual(rejected[3], rejected[4]));

        assertTrue(Arrays.areEqual(secret, kemExtractor.extractSecret(ct)));
    }

    private static byte[] hashWithPrefix(int prefix, byte[] a, byte[] b)
    {
        SHA512Digest digest = new SHA512Digest();
        digest.update((byte)prefix);
        digest.update(a, 0, a.length);
        digest.update(b, 0, b.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }
}
