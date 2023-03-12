package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
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

        TestSampler sampler = new TestSampler();
        for (int i = 0; i != paramList.length; i++)
        {
            SNTRUPrimeParameters paramSpec = paramList[i];
            System.out.println("****    Parameter Spec - '" + paramSpec.getName().toUpperCase() + "'    ****");
            InputStream resource = TestResourceFinder.findTestResource(resourcePath, paramSpec.getName().toLowerCase() + ".rsp");
            BufferedReader resourceReader = new BufferedReader(new InputStreamReader(resource));

            String line;
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
                System.out.println("Running Test-" + count + " ...");

                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                SNTRUPrimeKeyPairGenerator keyPairGenerator = new SNTRUPrimeKeyPairGenerator();
                keyPairGenerator.init(new SNTRUPrimeKeyGenerationParameters(random, paramSpec));

                AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
                assertTrue(Arrays.areEqual(pk, ((SNTRUPrimePublicKeyParameters)keyPair.getPublic()).getEncoded()));
                System.out.println("- Public Key matched ...");
                assertTrue(Arrays.areEqual(sk, ((SNTRUPrimePrivateKeyParameters)keyPair.getPrivate()).getEncoded()));
                System.out.println("- Private Key matched ...");

                SNTRUPrimeKEMGenerator kemGenerator = new SNTRUPrimeKEMGenerator(random);
                SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(keyPair.getPublic());

                assertTrue(Arrays.areEqual(ct, secretEncapsulation.getEncapsulation()));
                System.out.println("- Encapsulation Cipher Text matched ...");
                byte[] secret = secretEncapsulation.getSecret();
                assertTrue(Arrays.areEqual(ss, 0, secret.length, secret, 0, secret.length));
                System.out.println("- Encapsulation Shared Secret matched ...");

                SNTRUPrimeKEMExtractor kemExtractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters)keyPair.getPrivate());
                byte[] decryptedSecret = kemExtractor.extractSecret(ct);

                assertTrue(Arrays.areEqual(ss, 0, decryptedSecret.length, decryptedSecret, 0, decryptedSecret.length));
                System.out.println("- Decapsulation Shared Secret matched ...");
            }

            resource.close();
        }
    }
}
