package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * Multi-release regression test for the {@code javax.crypto.KEM} services.
 * <p>
 * The KEM {@code Encapsulator} / {@code Decapsulator} SPIs live only in the {@code jdk17} overlay,
 * so on a JDK 25 runtime they are loaded from {@code META-INF/versions/17} - while any class that
 * also has a {@code jdk25} twin is loaded from {@code META-INF/versions/25} instead. A helper the
 * SPIs call must therefore not be a method of an overlaid class. When the shared prologue was
 * briefly hosted on {@code org.bouncycastle.jcajce.util.SpiUtil}, which does have a jdk25 twin
 * (its {@code hasKDF()} differs there), every encapsulate and decapsulate threw
 * {@code NoSuchMethodError} on JDK 25 while JDK 21 was unaffected; the helpers live on the
 * never-overlaid {@code KemSpiUtil} for that reason.
 * <p>
 * This test has to be in {@code src/test/jdk25}: that is the only source set the {@code test25}
 * task runs, and {@code test25} is the only task that puts a JDK 25 runtime in front of the
 * multi-release jar. The {@code *KEM17Test} classes under {@code src/test/jdk17} cannot see this
 * class of failure, because there the SPIs and every hook class alike resolve from
 * {@code META-INF/versions/17} and no cross-overlay call happens.
 * <p>
 * All ten KEM families share the same two helpers, so one family from each of the two SPI package
 * trees is enough to catch a break: ML-KEM for {@code jcajce.provider.asymmetric} in the BC
 * provider, HQC for {@code pqc.jcajce.provider} in BCPQC.
 */
public class KemSpiMRTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testMLKEM()
        throws Exception
    {
        checkRoundTrip("ML-KEM", "ML-KEM", "BC", MLKEMParameterSpec.ml_kem_768);
    }

    public void testHQC()
        throws Exception
    {
        checkRoundTrip("HQC", "HQC", "BCPQC", HQCParameterSpec.hqc128);
    }

    private void checkRoundTrip(String kemName, String keyPairName, String provider,
                                AlgorithmParameterSpec spec)
        throws Exception
    {
        setUp();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(keyPairName, provider);
        kpGen.initialize(spec, new SecureRandom());
        KeyPair kp = kpGen.generateKeyPair();

        KEM kem = KEM.getInstance(kemName, provider);

        KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
        KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());

        KEM.Encapsulated encapsulated = enc.encapsulate();
        SecretKey recovered = dec.decapsulate(encapsulated.encapsulation());

        assertEquals(kemName + ": encapsulation size", enc.encapsulationSize(),
            encapsulated.encapsulation().length);
        assertTrue(kemName + ": both sides must agree on the secret",
            Arrays.constantTimeAreEqual(encapsulated.key().getEncoded(), recovered.getEncoded()));

        // a non-zero window as well, which is where each SPI's own from/to wiring shows up
        int secretSize = enc.secretSize();
        assertTrue(kemName + ": secret is too short to slice", secretSize > 1);

        KEM.Encapsulated sliced = enc.encapsulate(1, secretSize, "AES");
        SecretKey slicedBack = dec.decapsulate(sliced.encapsulation(), 1, secretSize, "AES");

        assertEquals(kemName + ": sliced secret length", secretSize - 1,
            sliced.key().getEncoded().length);
        assertTrue(kemName + ": both sides must agree on the sliced secret",
            Arrays.constantTimeAreEqual(sliced.key().getEncoded(), slicedBack.getEncoded()));
    }
}
