package org.bouncycastle.pqc.jcajce.provider.test;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.LMSKey;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * Code compiled against 1.86 calls the extractKeyShard() each deprecated pqc interface declares, so the
 * shard is extracted through that declaration, found by reflection to report a missing one as a failure.
 */
public class DeprecatedHashBasedKeyInterfaceTest
    extends TestCase
{
    private static final byte[] MSG = Strings.toByteArray("Hello, world!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testXMSSPrivateKeyShard()
        throws Exception
    {
        KeyPair kp = generateKeyPair("XMSS", new XMSSParameterSpec(4, XMSSParameterSpec.SHA256));

        XMSSPrivateKey privKey = (XMSSPrivateKey)kp.getPrivate();
        XMSSPrivateKey shard = (XMSSPrivateKey)extractKeyShard(XMSSPrivateKey.class, privKey, 2);

        assertEquals(2, privKey.getIndex());
        assertEquals(2, shard.getUsagesRemaining());

        checkSignature("XMSS", shard, kp);
    }

    public void testXMSSMTPrivateKeyShard()
        throws Exception
    {
        KeyPair kp = generateKeyPair("XMSSMT", new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHA256));

        XMSSMTPrivateKey privKey = (XMSSMTPrivateKey)kp.getPrivate();
        XMSSMTPrivateKey shard = (XMSSMTPrivateKey)extractKeyShard(XMSSMTPrivateKey.class, privKey, 2);

        assertEquals(2, privKey.getIndex());
        assertEquals(2, shard.getUsagesRemaining());

        checkSignature("XMSSMT", shard, kp);
    }

    public void testLMSPrivateKeyShard()
        throws Exception
    {
        KeyPair kp = generateKeyPair("LMS", new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4));

        LMSPrivateKey privKey = (LMSPrivateKey)kp.getPrivate();
        LMSPrivateKey shard = (LMSPrivateKey)extractKeyShard(LMSPrivateKey.class, privKey, 2);

        assertEquals(2, privKey.getIndex());
        assertEquals(2, shard.getUsagesRemaining());

        checkSignature("LMS", shard, kp);
    }

    public void testLMSPrivateKeyIsLMSKey()
        throws Exception
    {
        assertTrue("LMSPrivateKey should extend LMSKey", LMSKey.class.isAssignableFrom(LMSPrivateKey.class));

        KeyPair kp = generateKeyPair("LMS", new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4));

        assertTrue("LMS private key should be an LMSKey", kp.getPrivate() instanceof LMSKey);
        assertEquals(1, ((LMSKey)kp.getPrivate()).getLevels());
    }

    private static KeyPair generateKeyPair(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        kpGen.initialize(spec, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    /**
     * Extract a shard through the extractKeyShard() method the deprecated interface itself declares,
     * the one returning the deprecated type, rather than through the method it inherits.
     */
    private static Object extractKeyShard(Class deprecatedType, PrivateKey privKey, int usageCount)
        throws Exception
    {
        Method[] methods = deprecatedType.getDeclaredMethods();
        Method extract = null;

        for (int i = 0; i != methods.length; i++)
        {
            Method method = methods[i];
            Class[] params = method.getParameterTypes();

            if (method.getName().equals("extractKeyShard") && params.length == 1 && params[0] == int.class
                && method.getReturnType() == deprecatedType)
            {
                extract = method;
            }
        }

        assertNotNull(deprecatedType.getName() + " should declare extractKeyShard(int) returning " + deprecatedType.getName(), extract);
        assertTrue(deprecatedType.isInstance(privKey));

        Object shard = extract.invoke(privKey, new Object[]{ Integer.valueOf(usageCount) });

        assertTrue(deprecatedType.isInstance(shard));

        return shard;
    }

    private static void checkSignature(String algorithm, PrivateKey privKey, KeyPair kp)
        throws Exception
    {
        Signature signer = Signature.getInstance(algorithm, "BC");

        signer.initSign(privKey);
        signer.update(MSG);

        byte[] sig = signer.sign();

        signer.initVerify(kp.getPublic());
        signer.update(MSG);

        assertTrue(signer.verify(sig));
    }
}
