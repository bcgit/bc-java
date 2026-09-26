package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SmaugTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * The BCPQC keys report their parameter set through java.security.AsymmetricKey.getParams() as a
 * NamedParameterSpec (github #2467), and the name reported is one the family's KeyPairGenerator
 * accepts back. This runs against the multi-release jar, so it exercises the jdk1.11 copy of
 * NamedParameterSpecUtil reached from the base-tree key classes.
 */
public class PQCNamedKeyParamsMRTest
    extends TestCase
{
    private static final Object[][] FAMILIES = new Object[][]
        {
            {"AIMer", AIMerParameterSpec.aimer128f},
            {"BIKE", BIKEParameterSpec.bike128},
            {"FAEST", FaestParameterSpec.faest_128s},
            {"Falcon", FalconParameterSpec.falcon_512},
            {"HAETAE", HaetaeParameterSpec.haetae2},
            {"HQC", HQCParameterSpec.hqc128},
            {"Mayo", MayoParameterSpec.mayo1},
            {"MQOM", MQOMParameterSpec.mqom2_cat1_gf2_fast_r3},
            {"NTRU", NTRUParameterSpec.ntruhps2048509},
            {"NTRUPLUS", NTRUPlusParameterSpec.ntruplus_768},
            {"NTRULPRime", NTRULPRimeParameterSpec.ntrulpr653},
            {"SNTRUPrime", SNTRUPrimeParameterSpec.sntrup653},
            {"QRUOV", QRUOVParameterSpec.qruov1q127L3v156m54},
            {"SABER", SABERParameterSpec.lightsaberkem128r3},
            {"SDitH", SDitHParameterSpec.sdith_hypercube_cat1_gf256},
            {"SmaugT", SmaugTParameterSpec.smaugt_mode1},
            {"Snova", SnovaParameterSpec.SNOVA_24_5_4_SSK},
            {"SQIsign", SQIsignParameterSpec.sqisign_lvl1},
            {"UOV", UOVParameterSpec.uov_Is},
        };

    protected void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testKeyParams()
        throws Exception
    {
        for (int i = 0; i != FAMILIES.length; i++)
        {
            String family = (String)FAMILIES[i][0];
            AlgorithmParameterSpec spec = (AlgorithmParameterSpec)FAMILIES[i][1];
            String name = specName(spec);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(family, "BCPQC");
            kpg.initialize(spec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            assertEquals(family, name, paramsName(kp.getPublic()));
            assertEquals(family, name, paramsName(kp.getPrivate()));

            KeyFactory kf = KeyFactory.getInstance(family, "BCPQC");
            assertEquals(family, name,
                paramsName(kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()))));
            assertEquals(family, name,
                paramsName(kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()))));
        }
    }

    /**
     * What getParams() reports is accepted back by the family's KeyPairGenerator, in whatever case -
     * the Mayo, SDitH and Snova generators lower-cased a NamedParameterSpec name and then looked it
     * up in an upper-case table, so they refused every one.
     */
    public void testParamsAcceptedByKeyPairGenerator()
        throws Exception
    {
        for (int i = 0; i != FAMILIES.length; i++)
        {
            String family = (String)FAMILIES[i][0];
            String name = specName((AlgorithmParameterSpec)FAMILIES[i][1]);
            String[] names = new String[]{ name, Strings.toLowerCase(name), Strings.toUpperCase(name) };

            for (int j = 0; j != names.length; j++)
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(family, "BCPQC");
                try
                {
                    kpg.initialize(new NamedParameterSpec(names[j]), new SecureRandom());
                }
                catch (Exception e)
                {
                    fail(family + " refused NamedParameterSpec(\"" + names[j] + "\"): " + e);
                }
                assertEquals(family + " " + names[j], name, paramsName(kpg.generateKeyPair().getPublic()));
            }
        }
    }

    private static String specName(AlgorithmParameterSpec spec)
        throws Exception
    {
        return (String)spec.getClass().getMethod("getName").invoke(spec);
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
