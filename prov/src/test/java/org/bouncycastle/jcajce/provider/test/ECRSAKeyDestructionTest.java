package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.security.auth.Destroyable;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Verifies that the EC and RSA private keys honour the JCA {@link javax.security.auth.Destroyable}
 * contract, mirroring {@link PQCKeyDestructionTest} for the classical BigInteger-backed keys:
 * {@code destroy()} drops the held key material, {@code isDestroyed()} flips, the secret-bearing
 * accessors throw afterwards, a destroyed key cannot be serialized (IOException, not an escaping
 * IllegalStateException), and a get racing a destroy() only ever observes the intact value or the
 * "key destroyed" IllegalStateException. See github #2366.
 */
public class ECRSAKeyDestructionTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testDestroyErasesECPrivateKey()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        PrivateKey priv = kp.getPrivate();
        ECPrivateKey ecPriv = (ECPrivateKey)priv;

        byte[] enc = priv.getEncoded();
        assertNotNull("EC: no encoding", enc);
        assertTrue("EC: key must be destroyable", priv instanceof Destroyable);

        Destroyable dPriv = (Destroyable)priv;
        assertFalse("EC: key reported destroyed before destroy()", dPriv.isDestroyed());
        assertNotNull(ecPriv.getS());

        int preHashCode = priv.hashCode();

        PrivateKey copy = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
            .generatePrivate(new PKCS8EncodedKeySpec(enc));
        assertEquals("EC: copy should equal original before destroy()", priv, copy);

        ECPrivateKeyParameters baseKey = ((BCECPrivateKey)priv).engineGetKeyParameters();
        assertTrue("EC: lightweight key must be destroyable", baseKey instanceof Destroyable);

        // must succeed without throwing DestroyFailedException
        dPriv.destroy();

        assertTrue("EC: key not reported destroyed after destroy()", dPriv.isDestroyed());
        assertTrue("EC: lightweight key not destroyed with the JCA key", ((Destroyable)baseKey).isDestroyed());

        try
        {
            priv.getEncoded();
            fail("EC: getEncoded() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            ecPriv.getS();
            fail("EC: getS() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            ((BCECPrivateKey)priv).getD();
            fail("EC: getD() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            baseKey.getD();
            fail("EC: lightweight getD() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        // the public domain parameters remain, hashCode is stable, and equality collapses to identity
        assertNotNull("EC: domain parameters should survive destroy()", ecPriv.getParams());
        assertEquals("EC: hashCode should be stable across destroy()", preHashCode, priv.hashCode());
        assertTrue("EC: destroyed key should still equal itself", priv.equals(priv));
        assertFalse("EC: destroyed key should not equal a live copy", priv.equals(copy));
        assertFalse("EC: live copy should not equal a destroyed key", copy.equals(priv));
        assertNotNull("EC: toString() should not throw once destroyed", priv.toString());

        checkSerializationFails("EC", priv);

        // destroy() is idempotent - a second call must not throw
        dPriv.destroy();
        assertTrue(dPriv.isDestroyed());
    }

    public void testDestroyErasesRSAPrivateKey()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        PrivateKey priv = kp.getPrivate();
        RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey)priv;

        byte[] enc = priv.getEncoded();
        assertNotNull("RSA: no encoding", enc);
        assertTrue("RSA: key must be destroyable", priv instanceof Destroyable);

        Destroyable dPriv = (Destroyable)priv;
        assertFalse("RSA: key reported destroyed before destroy()", dPriv.isDestroyed());

        BigInteger preModulus = rsaPriv.getModulus();
        BigInteger prePublicExponent = rsaPriv.getPublicExponent();
        int preHashCode = priv.hashCode();

        PrivateKey copy = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
            .generatePrivate(new PKCS8EncodedKeySpec(enc));
        assertEquals("RSA: copy should equal original before destroy()", priv, copy);

        // must succeed without throwing DestroyFailedException
        dPriv.destroy();

        assertTrue("RSA: key not reported destroyed after destroy()", dPriv.isDestroyed());

        try
        {
            priv.getEncoded();
            fail("RSA: getEncoded() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        checkSecretAccessorsThrow(rsaPriv);

        // the public components remain, hashCode is stable, and equality collapses to identity
        assertEquals("RSA: modulus should survive destroy()", preModulus, rsaPriv.getModulus());
        assertEquals("RSA: public exponent should survive destroy()", prePublicExponent, rsaPriv.getPublicExponent());
        assertEquals("RSA: hashCode should be stable across destroy()", preHashCode, priv.hashCode());
        assertTrue("RSA: destroyed key should still equal itself", priv.equals(priv));
        assertFalse("RSA: destroyed key should not equal a live copy", priv.equals(copy));
        assertFalse("RSA: live copy should not equal a destroyed key", copy.equals(priv));
        assertNotNull("RSA: toString() should not throw once destroyed", priv.toString());

        checkSerializationFails("RSA", priv);

        // destroy() is idempotent - a second call must not throw
        dPriv.destroy();
        assertTrue(dPriv.isDestroyed());
    }

    public void testLightweightParametersDestroy()
        throws Exception
    {
        // EC
        X9ECParameters x9 = CustomNamedCurves.getByName("P-256");
        ECDomainParameters domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
        ECPrivateKeyParameters ecKey = new ECPrivateKeyParameters(new BigInteger("1234567890abcdef1234567890abcdef", 16), domain);

        assertTrue("EC params: must be destroyable", ecKey instanceof Destroyable);
        assertFalse(((Destroyable)ecKey).isDestroyed());

        ((Destroyable)ecKey).destroy();

        assertTrue(((Destroyable)ecKey).isDestroyed());
        try
        {
            ecKey.getD();
            fail("EC params: getD() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
        assertNotNull("EC params: domain parameters should survive destroy()", ecKey.getParameters());

        // RSA - base and CRT parameters, from one generated key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        RSAPrivateCrtKey k = (RSAPrivateCrtKey)kpg.generateKeyPair().getPrivate();

        RSAKeyParameters baseKey = new RSAKeyParameters(true, k.getModulus(), k.getPrivateExponent());

        assertTrue("RSA params: must be destroyable", baseKey instanceof Destroyable);
        assertFalse(((Destroyable)baseKey).isDestroyed());

        ((Destroyable)baseKey).destroy();

        assertTrue(((Destroyable)baseKey).isDestroyed());
        try
        {
            baseKey.getExponent();
            fail("RSA params: getExponent() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
        assertEquals("RSA params: modulus should survive destroy()", k.getModulus(), baseKey.getModulus());

        RSAPrivateCrtKeyParameters crtKey = new RSAPrivateCrtKeyParameters(k.getModulus(),
            k.getPublicExponent(), k.getPrivateExponent(),
            k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());

        assertTrue("RSA CRT params: must be destroyable", crtKey instanceof Destroyable);

        ((Destroyable)crtKey).destroy();

        assertTrue(((Destroyable)crtKey).isDestroyed());
        checkCrtParametersSecretAccessorsThrow(crtKey);
        assertEquals("RSA CRT params: modulus should survive destroy()", k.getModulus(), crtKey.getModulus());
        assertEquals("RSA CRT params: public exponent should survive destroy()", k.getPublicExponent(), crtKey.getPublicExponent());
    }

    /**
     * A get racing a destroy() must only ever observe the intact value or the "key destroyed"
     * IllegalStateException - never null, a partial value or an unexpected exception - and once
     * a reader has observed the destruction it must be permanent.
     */
    public void testDestroyDuringGetNeverLeaksAValue()
        throws Exception
    {
        X9ECParameters x9 = CustomNamedCurves.getByName("P-256");
        final ECDomainParameters domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
        final BigInteger d = new BigInteger("1234567890abcdef1234567890abcdef", 16);

        for (int round = 0; round != 200; round++)
        {
            final ECPrivateKeyParameters key = new ECPrivateKeyParameters(d, domain);
            assertTrue(key instanceof Destroyable);

            final StringBuffer anomalies = new StringBuffer();

            Thread[] readers = new Thread[2];
            for (int t = 0; t != readers.length; t++)
            {
                readers[t] = new Thread()
                {
                    public void run()
                    {
                        for (int i = 0; i != 2000; i++)
                        {
                            try
                            {
                                BigInteger value = key.getD();
                                if (value == null)
                                {
                                    anomalies.append("[null value handed out]");
                                }
                                else if (!d.equals(value))
                                {
                                    anomalies.append("[wrong value handed out]");
                                }
                            }
                            catch (IllegalStateException e)
                            {
                                if (!"key destroyed".equals(e.getMessage()))
                                {
                                    anomalies.append("[unexpected message: " + e.getMessage() + "]");
                                }

                                // once destruction has been observed it must be permanent
                                try
                                {
                                    key.getD();
                                    anomalies.append("[value handed out after destruction was observed]");
                                }
                                catch (IllegalStateException expected)
                                {
                                    // expected
                                }
                                return;
                            }
                            catch (RuntimeException e)
                            {
                                anomalies.append("[unexpected exception: " + e + "]");
                                return;
                            }
                        }
                    }
                };
            }

            for (int t = 0; t != readers.length; t++)
            {
                readers[t].start();
            }

            ((Destroyable)key).destroy();

            for (int t = 0; t != readers.length; t++)
            {
                readers[t].join();
            }

            try
            {
                key.getD();
                fail("getD() should throw after destroy() returned");
            }
            catch (IllegalStateException e)
            {
                assertEquals("key destroyed", e.getMessage());
            }

            assertEquals("anomalies in round " + round + ": " + anomalies, 0, anomalies.length());
        }

        // same shape for the RSA CRT accessors (isInternal skips modulus validation - the race
        // is about reference semantics, not the arithmetic)
        final BigInteger p = BigInteger.valueOf(61);

        for (int round = 0; round != 100; round++)
        {
            final RSAPrivateCrtKeyParameters key = new RSAPrivateCrtKeyParameters(
                BigInteger.valueOf(3233), BigInteger.valueOf(17), BigInteger.valueOf(2753),
                p, BigInteger.valueOf(53), BigInteger.valueOf(53), BigInteger.valueOf(49), BigInteger.valueOf(38), true);

            final StringBuffer anomalies = new StringBuffer();

            Thread reader = new Thread()
            {
                public void run()
                {
                    for (int i = 0; i != 2000; i++)
                    {
                        try
                        {
                            BigInteger value = key.getP();
                            if (value == null)
                            {
                                anomalies.append("[null value handed out]");
                            }
                            else if (!p.equals(value))
                            {
                                anomalies.append("[wrong value handed out]");
                            }
                        }
                        catch (IllegalStateException e)
                        {
                            if (!"key destroyed".equals(e.getMessage()))
                            {
                                anomalies.append("[unexpected message: " + e.getMessage() + "]");
                            }
                            return;
                        }
                        catch (RuntimeException e)
                        {
                            anomalies.append("[unexpected exception: " + e + "]");
                            return;
                        }
                    }
                }
            };

            reader.start();
            ((Destroyable)key).destroy();
            reader.join();

            try
            {
                key.getP();
                fail("getP() should throw after destroy() returned");
            }
            catch (IllegalStateException e)
            {
                assertEquals("key destroyed", e.getMessage());
            }

            assertEquals("anomalies in round " + round + ": " + anomalies, 0, anomalies.length());
        }
    }

    private void checkSecretAccessorsThrow(RSAPrivateCrtKey rsaPriv)
    {
        try
        {
            rsaPriv.getPrivateExponent();
            fail("RSA: getPrivateExponent() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            rsaPriv.getPrimeP();
            fail("RSA: getPrimeP() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            rsaPriv.getPrimeQ();
            fail("RSA: getPrimeQ() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            rsaPriv.getPrimeExponentP();
            fail("RSA: getPrimeExponentP() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            rsaPriv.getPrimeExponentQ();
            fail("RSA: getPrimeExponentQ() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            rsaPriv.getCrtCoefficient();
            fail("RSA: getCrtCoefficient() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }

    private void checkCrtParametersSecretAccessorsThrow(RSAPrivateCrtKeyParameters crtKey)
    {
        try
        {
            crtKey.getExponent();
            fail("RSA CRT params: getExponent() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            crtKey.getP();
            fail("RSA CRT params: getP() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            crtKey.getQ();
            fail("RSA CRT params: getQ() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            crtKey.getDP();
            fail("RSA CRT params: getDP() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            crtKey.getDQ();
            fail("RSA CRT params: getDQ() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            crtKey.getQInv();
            fail("RSA CRT params: getQInv() should throw once destroyed");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }

    private void checkSerializationFails(String algorithm, PrivateKey priv)
        throws Exception
    {
        ObjectOutputStream oOut = new ObjectOutputStream(new ByteArrayOutputStream());
        try
        {
            oOut.writeObject(priv);
            fail(algorithm + ": serialization should throw once destroyed");
        }
        catch (IOException e)
        {
            // expected - the declared exception, carrying the destroyed message
            assertEquals("key destroyed", e.getMessage());
        }
        catch (IllegalStateException e)
        {
            fail(algorithm + ": IllegalStateException must not escape writeObject");
        }
    }
}
