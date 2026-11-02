package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
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
                NISTSecureRandom random = new NISTSecureRandom(seed, null);
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
     * A ciphertext changed anywhere decapsulates, by implicit rejection, to a secret of its own rather than the
     * encapsulated one, and the same one each time.
     */
    public void testImplicitRejection()
    {
        SecureRandom random = new SecureRandom();
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(random, NTRULPRimeParameters.ntrulpr761));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        SecretWithEncapsulation secretEncapsulation = new NTRULPRimeKEMGenerator(random).generateEncapsulated(
            keyPair.getPublic());
        byte[] secret = secretEncapsulation.getSecret();
        byte[] ct = secretEncapsulation.getEncapsulation();

        NTRULPRimeKEMExtractor kemExtractor = new NTRULPRimeKEMExtractor(
            (NTRULPRimePrivateKeyParameters)keyPair.getPrivate());

        // the first byte, the last bytes of the rounded polynomial and of T, and the confirmation hash
        int[] positions = { 0, ct.length - 161, ct.length - 33, ct.length - 1 };
        for (int k = 0; k != positions.length; k++)
        {
            byte[] tampered = Arrays.clone(ct);
            tampered[positions[k]] ^= (byte)0x80;

            byte[] rejected = kemExtractor.extractSecret(tampered);
            assertFalse(Arrays.areEqual(secret, rejected));
            assertTrue(Arrays.areEqual(rejected, kemExtractor.extractSecret(tampered)));
        }

        assertTrue(Arrays.areEqual(secret, kemExtractor.extractSecret(ct)));
    }
}
