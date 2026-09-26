package org.bouncycastle.jcajce.provider.test;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The BC ML-DSA, ML-KEM and SLH-DSA keys report their parameter set through
 * java.security.AsymmetricKey.getParams() as a NamedParameterSpec, as the JDK's own keys do
 * (github #2467). This runs against the multi-release jar, so it exercises the jdk1.11 copy of
 * NamedParameterSpecUtil reached from the base-tree key classes.
 */
public class NamedKeyParamsMRTest
    extends TestCase
{
    private static final String[] BC_ONLY = new String[]
        {
            "ML-DSA-44-WITH-SHA512", "ML-DSA-65-WITH-SHA512", "ML-DSA-87-WITH-SHA512",
            "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128F", "SLH-DSA-SHA2-192F", "SLH-DSA-SHAKE-256F",
            "SLH-DSA-SHA2-128S-WITH-SHA256"
        };

    private static final String[] SHARED = new String[]
        {
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
        };

    protected void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testBCKeyParams()
        throws Exception
    {
        for (int i = 0; i != SHARED.length; i++)
        {
            checkBCKeyPair(SHARED[i]);
        }
        for (int i = 0; i != BC_ONLY.length; i++)
        {
            checkBCKeyPair(BC_ONLY[i]);
        }
    }

    /**
     * A key BC and the JDK both implement names the same parameter set through getParams(),
     * whichever provider decoded it, although getAlgorithm() differs ("ML-DSA-65" / "ML-DSA").
     */
    public void testMatchesSunKeyParams()
        throws Exception
    {
        for (int i = 0; i != SHARED.length; i++)
        {
            String name = SHARED[i];
            KeyPair bcKp = KeyPairGenerator.getInstance(name, "BC").generateKeyPair();

            // the JDK registers ML-DSA in SUN and ML-KEM in SunJCE
            String jdkProv = name.startsWith("ML-KEM") ? "SunJCE" : "SUN";
            KeyFactory sunKf = KeyFactory.getInstance(name, jdkProv);
            PublicKey sunPub = sunKf.generatePublic(new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
            assertEquals(name, paramsName(sunPub));
            assertEquals(paramsName(sunPub), paramsName(bcKp.getPublic()));

            // JDK 25 only reads the expanded-key form of an ML-DSA / ML-KEM private key.
            PrivateKey bcPriv = bcKp.getPrivate();
            byte[] privEnc = (bcPriv instanceof MLDSAPrivateKey)
                ? ((MLDSAPrivateKey)bcPriv).getPrivateKey(false).getEncoded()
                : ((MLKEMPrivateKey)bcPriv).getPrivateKey(false).getEncoded();
            PrivateKey sunPriv = sunKf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));
            assertEquals(paramsName(sunPriv), paramsName(bcPriv));

            KeyPair sunKp = KeyPairGenerator.getInstance(name, jdkProv).generateKeyPair();
            KeyFactory bcKf = KeyFactory.getInstance(name, "BC");
            PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(sunKp.getPublic().getEncoded()));
            assertEquals(paramsName(sunKp.getPublic()), paramsName(bcPub));
        }
    }

    private void checkBCKeyPair(String name)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(name, "BC").generateKeyPair();
        assertEquals(name, paramsName(kp.getPublic()));
        assertEquals(name, paramsName(kp.getPrivate()));

        KeyFactory kf = KeyFactory.getInstance(name, "BC");
        assertEquals(name, paramsName(kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()))));
        assertEquals(name, paramsName(kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()))));
    }

    private static String paramsName(Key key)
    {
        // called through the JDK interfaces, as a JCA caller would, not the BC key classes
        AlgorithmParameterSpec params = (key instanceof PublicKey)
            ? ((PublicKey)key).getParams() : ((PrivateKey)key).getParams();
        assertTrue(key.getAlgorithm() + ": " + params, params instanceof NamedParameterSpec);
        return ((NamedParameterSpec)params).getName();
    }
}
