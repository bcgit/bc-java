package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * An NTRUPlusKEMExtractor holds one NTRUPlusEngine for its lifetime, so the engine must not carry
 * mutable state across a call. It used to keep a single SHAKE instance in a field: two threads
 * extracting through one extractor interleaved their absorb/squeeze phases, which produced wrong
 * shared secrets and threw {@code IllegalStateException: attempt to absorb with odd length queue}.
 * The digest is now built per call, as CMCEEngine's already was.
 * <p>
 * The generator side is exercised too, since NTRUPlusKEMGenerator builds an engine per call but its
 * KEM keys and parameters are shared - and NTRUPlusParameters hands every engine the same zetas
 * array, so a write to it would corrupt globally.
 */
public class NTRUPlusConcurrencyTest
    extends TestCase
{
    private static final int VECTORS = 16;
    private static final int THREADS = 4;

    public void testConcurrentExtraction()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        NTRUPlusKeyPairGenerator kpg = new NTRUPlusKeyPairGenerator();
        kpg.init(new NTRUPlusKeyGenerationParameters(random, NTRUPlusParameters.ntruplus_kem_768));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        final NTRUPlusPublicKeyParameters pub = (NTRUPlusPublicKeyParameters)kp.getPublic();
        NTRUPlusPrivateKeyParameters priv = (NTRUPlusPrivateKeyParameters)kp.getPrivate();

        final byte[][] encapsulations = new byte[VECTORS][];
        final byte[][] expected = new byte[VECTORS][];

        NTRUPlusKEMGenerator gen = new NTRUPlusKEMGenerator(random);
        for (int i = 0; i != VECTORS; i++)
        {
            SecretWithEncapsulation enc = gen.generateEncapsulated(pub);
            encapsulations[i] = enc.getEncapsulation();
            expected[i] = enc.getSecret();
        }

        // one extractor, shared across threads
        final NTRUPlusKEMExtractor extractor = new NTRUPlusKEMExtractor(priv);
        final Throwable[] failure = new Throwable[1];
        final int[] mismatches = new int[1];

        Thread[] threads = new Thread[THREADS];
        for (int t = 0; t != THREADS; t++)
        {
            threads[t] = new Thread()
            {
                public void run()
                {
                    for (int i = 0; i != VECTORS; i++)
                    {
                        try
                        {
                            byte[] secret = extractor.extractSecret(encapsulations[i]);
                            if (!Arrays.areEqual(secret, expected[i]))
                            {
                                synchronized (mismatches)
                                {
                                    mismatches[0]++;
                                }
                            }
                        }
                        catch (Throwable th)
                        {
                            failure[0] = th;
                        }
                    }
                }
            };
            threads[t].start();
        }
        for (int t = 0; t != THREADS; t++)
        {
            threads[t].join();
        }

        assertNull("shared extractor threw " + failure[0], failure[0]);
        assertEquals("shared extractor produced wrong secrets", 0, mismatches[0]);
    }

    public void testConcurrentEncapsulation()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        NTRUPlusKeyPairGenerator kpg = new NTRUPlusKeyPairGenerator();
        kpg.init(new NTRUPlusKeyGenerationParameters(random, NTRUPlusParameters.ntruplus_kem_768));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        final NTRUPlusPublicKeyParameters pub = (NTRUPlusPublicKeyParameters)kp.getPublic();
        final NTRUPlusKEMExtractor extractor =
            new NTRUPlusKEMExtractor((NTRUPlusPrivateKeyParameters)kp.getPrivate());

        // one generator, shared across threads - each encapsulation must round trip
        final NTRUPlusKEMGenerator gen = new NTRUPlusKEMGenerator(random);
        final Throwable[] failure = new Throwable[1];
        final int[] mismatches = new int[1];

        Thread[] threads = new Thread[THREADS];
        for (int t = 0; t != THREADS; t++)
        {
            threads[t] = new Thread()
            {
                public void run()
                {
                    for (int i = 0; i != VECTORS; i++)
                    {
                        try
                        {
                            SecretWithEncapsulation enc = gen.generateEncapsulated(pub);
                            byte[] secret;
                            synchronized (extractor)
                            {
                                secret = extractor.extractSecret(enc.getEncapsulation());
                            }
                            if (!Arrays.areEqual(secret, enc.getSecret()))
                            {
                                synchronized (mismatches)
                                {
                                    mismatches[0]++;
                                }
                            }
                        }
                        catch (Throwable th)
                        {
                            failure[0] = th;
                        }
                    }
                }
            };
            threads[t].start();
        }
        for (int t = 0; t != THREADS; t++)
        {
            threads[t].join();
        }

        assertNull("shared generator threw " + failure[0], failure[0]);
        assertEquals("shared generator produced unrecoverable encapsulations", 0, mismatches[0]);
    }
}
