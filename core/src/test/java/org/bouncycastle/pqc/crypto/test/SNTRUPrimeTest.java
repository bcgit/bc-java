package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class SNTRUPrimeTest
    extends TestCase
{
    private static final String resourcePath = "pqc/crypto/ntruprime/sntrup/";

    public void testKEM()
            throws Exception
    {
        SNTRUPrimeParameters[] paramList = new SNTRUPrimeParameters[]
        {
                SNTRUPrimeParameters.sntrup653,
                SNTRUPrimeParameters.sntrup761,
                SNTRUPrimeParameters.sntrup857,
                SNTRUPrimeParameters.sntrup953,
                SNTRUPrimeParameters.sntrup1013,
                SNTRUPrimeParameters.sntrup1277
        };

        for (int i = 0; i != paramList.length; i++)
        {
            SNTRUPrimeParameters paramSpec = paramList[i];
            // System.out.println("****    Parameter Spec - '" + paramSpec.getName().toUpperCase() + "'    ****");
            InputStream resource = TestResourceFinder.findTestResource(resourcePath, Strings.toLowerCase(paramSpec.getName()) + ".rsp");
            BufferedReader resourceReader = new BufferedReader(new InputStreamReader(resource));

            String line;
            TestSampler sampler = new TestSampler();
            while ((line = resourceReader.readLine()) != null)
            {
                if (! line.startsWith("count"))
                    continue;

                int a = line.indexOf("=");
                int count = Integer.parseInt(line.substring(a + 1).trim());
                line = resourceReader.readLine(); a = line.indexOf("=");
                byte[] seed = Hex.decode(line.substring(a + 1).trim());
                line = resourceReader.readLine(); a = line.indexOf("=");
                byte[] pk = Hex.decode(line.substring(a + 1).trim());
                line = resourceReader.readLine(); a = line.indexOf("=");
                byte[] sk = Hex.decode(line.substring(a + 1).trim());
                line = resourceReader.readLine(); a = line.indexOf("=");
                byte[] ct = Hex.decode(line.substring(a + 1).trim());
                line = resourceReader.readLine(); a = line.indexOf("=");
                byte[] ss = Hex.decode(line.substring(a + 1).trim());

                if (sampler.skipTest(count))
                {
                    continue;
                }
                // System.out.println("Running Test-" + count + " ...");

                SecureRandom random = new ReferenceDrawsRandom(new NISTSecureRandom(seed, null), 4 * paramSpec.getP());
                SNTRUPrimeKeyPairGenerator keyPairGenerator = new SNTRUPrimeKeyPairGenerator();
                keyPairGenerator.init(new SNTRUPrimeKeyGenerationParameters(random, paramSpec));

                AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
                assertTrue(Arrays.areEqual(pk, ((SNTRUPrimePublicKeyParameters)keyPair.getPublic()).getEncoded()));
                // System.out.println("- Public Key matched ...");
                assertTrue(Arrays.areEqual(sk, ((SNTRUPrimePrivateKeyParameters)keyPair.getPrivate()).getEncoded()));
                // System.out.println("- Private Key matched ...");

                SNTRUPrimeKEMGenerator kemGenerator = new SNTRUPrimeKEMGenerator(random);
                SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(keyPair.getPublic());

                assertTrue(Arrays.areEqual(ct, secretEncapsulation.getEncapsulation()));
                // System.out.println("- Encapsulation Cipher Text matched ...");
                byte[] secret = secretEncapsulation.getSecret();
                assertTrue(Arrays.areEqual(ss, 0, secret.length, secret, 0, secret.length));
                // System.out.println("- Encapsulation Shared Secret matched ...");

                SNTRUPrimeKEMExtractor kemExtractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters)keyPair.getPrivate());
                byte[] decryptedSecret = kemExtractor.extractSecret(ct);

                assertTrue(Arrays.areEqual(ss, 0, decryptedSecret.length, decryptedSecret, 0, decryptedSecret.length));
                // System.out.println("- Decapsulation Shared Secret matched ...");
            }

            resource.close();
        }
    }

    /**
     * A ciphertext changed anywhere decapsulates, by implicit rejection, to the secret the reference derives from rho
     * and the received ciphertext, SHA-512(0 | SHA-512(3 | rho)[0:32] | ciphertext)[0:32], rather than the
     * encapsulated one.
     * <p>
     * The secret used to be derived from the re-encrypted ciphertext instead, which depends only on the decrypted r,
     * so ciphertexts that decrypt to the same r - such as two that differ only in the confirmation hash - shared a
     * rejection secret, telling an attacker so.
     */
    public void testImplicitRejection()
    {
        SecureRandom random = new SecureRandom();
        SNTRUPrimeKeyPairGenerator keyPairGenerator = new SNTRUPrimeKeyPairGenerator();
        keyPairGenerator.init(new SNTRUPrimeKeyGenerationParameters(random, SNTRUPrimeParameters.sntrup761));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        SNTRUPrimePrivateKeyParameters privateKey = (SNTRUPrimePrivateKeyParameters)keyPair.getPrivate();

        SecretWithEncapsulation secretEncapsulation = new SNTRUPrimeKEMGenerator(random).generateEncapsulated(
            keyPair.getPublic());
        byte[] secret = secretEncapsulation.getSecret();
        byte[] ct = secretEncapsulation.getEncapsulation();

        SNTRUPrimeKEMExtractor kemExtractor = new SNTRUPrimeKEMExtractor(privateKey);
        byte[] hashRho = Arrays.copyOfRange(hashWithPrefix(3, privateKey.getRho(), new byte[0]), 0, 32);

        // the first byte, the last byte of the rounded polynomial, and the confirmation hash (twice)
        int[] positions = { 0, ct.length - 33, ct.length - 1, ct.length - 1 };
        byte[][] rejected = new byte[positions.length][];
        for (int k = 0; k != positions.length; k++)
        {
            byte[] tampered = Arrays.clone(ct);
            tampered[positions[k]] ^= (byte)(0x80 >>> k);

            rejected[k] = kemExtractor.extractSecret(tampered);
            assertFalse(Arrays.areEqual(secret, rejected[k]));
            assertTrue(Arrays.areEqual(Arrays.copyOfRange(hashWithPrefix(0, hashRho, tampered), 0, 32), rejected[k]));
        }

        // a changed confirmation hash decrypts to the same r, so re-encrypts to ct: not what the secret depends on
        assertFalse(Arrays.areEqual(Arrays.copyOfRange(hashWithPrefix(0, hashRho, ct), 0, 32), rejected[2]));
        assertFalse(Arrays.areEqual(rejected[2], rejected[3]));

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
