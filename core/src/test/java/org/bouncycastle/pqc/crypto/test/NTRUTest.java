package org.bouncycastle.pqc.crypto.test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.List;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PQCOtherInfoGenerator;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KAT tests for round 3 NTRU algorithm.
 */
public class NTRUTest
    extends TestCase
{
    private final String KAT_ROOT = "/org/bouncycastle/pqc/crypto/test/ntru/";
    private final NTRUParameters[] params = {
        NTRUParameters.ntruhps2048509,
        NTRUParameters.ntruhps2048677,
        NTRUParameters.ntruhps4096821,
        NTRUParameters.ntruhrss701
    };
    private final String[] katBase = {
        "ntruhps2048509",
        "ntruhps2048677",
        "ntruhps4096821",
        "ntruhrss701"
    };
    private final String[] katFiles = {
        "PQCkemKAT_935.rsp",
        "PQCkemKAT_1234.rsp",
        "PQCkemKAT_1590.rsp",
        "PQCkemKAT_1450.rsp"
    };

    public void testPrivInfoGeneration()
        throws IOException
    {
        SecureRandom random = new SecureRandom();
        PQCOtherInfoGenerator.PartyU partyU = new PQCOtherInfoGenerator.PartyU(NTRUParameters.ntruhrss701, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partA = partyU.getSuppPrivInfoPartA();

        PQCOtherInfoGenerator.PartyV partyV = new PQCOtherInfoGenerator.PartyV(NTRUParameters.ntruhrss701, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), Hex.decode("beef"), Hex.decode("cafe"), random);

        byte[] partB = partyV.getSuppPrivInfoPartB(partA);

        DEROtherInfo otherInfoU = partyU.generate(partB);

        DEROtherInfo otherInfoV = partyV.generate();

        Assert.assertTrue(Arrays.areEqual(otherInfoU.getEncoded(), otherInfoV.getEncoded()));
    }

    public void testPQCgenKAT_kem()
        throws FileNotFoundException
    {
        for (int i = 0; i < this.params.length; i++)
        {
            NTRUParameters param = params[i];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/" + katBase[i], katFiles[i]);
            List<NTRUKAT> kats = NTRUKAT.getKAT(src);

            for (int j = 0; j != kats.size(); j++)
            {
                NTRUKAT kat = (NTRUKAT)kats.get(j);
                SecureRandom random = new NISTSecureRandom(kat.seed, null);

                // test keygen
                NTRUKeyGenerationParameters keygenParams = new NTRUKeyGenerationParameters(random, param);
                NTRUKeyPairGenerator keygen = new NTRUKeyPairGenerator();
                keygen.init(keygenParams);
                AsymmetricCipherKeyPair keyPair = keygen.generateKeyPair();
                try
                {
                    Assert.assertTrue(Arrays.areEqual(kat.pk, ((NTRUPublicKeyParameters)keyPair.getPublic()).getPublicKey()));
                    Assert.assertTrue(Arrays.areEqual(kat.sk, ((NTRUPrivateKeyParameters)keyPair.getPrivate()).getPrivateKey()));
                }
                catch (AssertionError e)
                {
                    System.err.println("Failure at keygen");
                    System.err.println("KAT: " + katFiles[i]);
                    System.err.println("count: " + kat.count);
                    System.err.println("expected (pk): " + Hex.toHexString(kat.pk));
                    System.err.println("actual (pk): " + Hex.toHexString(((NTRUPublicKeyParameters)keyPair.getPublic()).getPublicKey()));
                    System.err.println("expected (sk): " + Hex.toHexString(kat.sk));
                    System.err.println("actual (sk): " + Hex.toHexString(((NTRUPrivateKeyParameters)keyPair.getPrivate()).getPrivateKey()));
                    throw new AssertionError(e);
                }

                // test encapsulate
                NTRUPublicKeyParameters pk = new NTRUPublicKeyParameters(param, kat.pk);
                NTRUKEMGenerator encapsulator = new NTRUKEMGenerator(random);
                SecretWithEncapsulation encapsulation = encapsulator.generateEncapsulated(pk);
                byte[] secret = encapsulation.getSecret();
                try
                {
                    // the KATs are based on 256 bit secrets
                    Assert.assertTrue(Arrays.areEqual(kat.ss, 0, secret.length, secret, 0, secret.length));
                    Assert.assertTrue(Arrays.areEqual(kat.ct, encapsulation.getEncapsulation()));
                }
                catch (AssertionError e)
                {
                    System.err.println("Failure at encapsulate");
                    System.err.println("KAT: " + katFiles[i]);
                    System.err.println("count: " + kat.count);
                    System.err.println("expected (ss): " + Hex.toHexString(kat.ss));
                    System.err.println("actual (ss): " + Hex.toHexString(secret));
                    System.err.println("expected (ct): " + Hex.toHexString(kat.ct));
                    System.err.println("actual (ct): " + Hex.toHexString(encapsulation.getEncapsulation()));
                    throw new AssertionError(e);
                }

                // test decapsulate
                NTRUPrivateKeyParameters sk = new NTRUPrivateKeyParameters(param, kat.sk);
                NTRUKEMExtractor decapsulator = new NTRUKEMExtractor(sk);
                byte[] ss = new byte[kat.ss.length];
                try
                {
                    ss = decapsulator.extractSecret(kat.ct);
                    Assert.assertTrue(Arrays.areEqual(kat.ss, 0, ss.length, ss, 0, ss.length));
                }
                catch (AssertionError e)
                {
                    System.err.println("Failure at decapsulate");
                    System.err.println("KAT: " + katFiles[i]);
                    System.err.println("count: " + kat.count);
                    System.err.println("expected (ss): " + Hex.toHexString(kat.ss));
                    System.err.println("actual (ss): " + Hex.toHexString(ss));
                    throw new AssertionError(e);
                }
            }
        }
    }
}
