package org.bouncycastle.pqc.jcajce.provider.test;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;

/**
 * Regression tests for the PQC <code>*ParameterSpec.fromName(String)</code> contract.
 * <p>
 * Every parameterized spec in this family exposes a <code>getName()</code> accessor and a
 * static <code>fromName(String)</code> lookup, and the key classes implement
 * <code>getParameterSpec()</code> as <code>fromName(params.getParameters().getName())</code>.
 * That only works if <code>fromName(spec.getName()) == spec</code> for every static instance;
 * when the lookup map is mis-keyed (or never populated) <code>getParameterSpec()</code> returns
 * null and a caller doing <code>key.getParameterSpec().getName()</code> gets an NPE.
 * </p>
 */
public class ParameterSpecRoundTripTest
    extends TestCase
{
    /**
     * Every PQC {@code *ParameterSpec} with a {@code getName()}/{@code fromName(String)} pair.
     * <p>
     * {@code NTRUPlusParameterSpec} is deliberately omitted: it has the same fromName
     * mis-keying defect, tracked and fixed separately (see COVERAGE_BUGS_HANDOVER.md #1).
     * Add it here once that fix has landed on main so it is covered too.
     * </p>
     */
    private static final String[] SPEC_CLASSES =
        {
            "org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.HawkParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec",
            "org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec",
            "org.bouncycastle.jcajce.spec.MLKEMParameterSpec",
            "org.bouncycastle.jcajce.spec.MLDSAParameterSpec",
            "org.bouncycastle.jcajce.spec.SLHDSAParameterSpec",
            "org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec",
        };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /**
     * Sweeps every spec class above: for each {@code public static final} instance of the spec
     * type, asserts {@code fromName(instance.getName()) == instance}. This is the property that
     * {@code Kyber/SABER/HQC/Snova} all violated, and a guard against future regressions.
     */
    public void testSpecFromNameRoundTrip()
        throws Exception
    {
        StringBuilder failures = new StringBuilder();
        int checked = 0;

        for (int c = 0; c != SPEC_CLASSES.length; c++)
        {
            Class cls = Class.forName(SPEC_CLASSES[c]);
            Method fromName = cls.getMethod("fromName", String.class);
            Method getName = cls.getMethod("getName");

            Field[] fields = cls.getDeclaredFields();
            for (int i = 0; i != fields.length; i++)
            {
                Field f = fields[i];
                if (Modifier.isStatic(f.getModifiers()) && Modifier.isPublic(f.getModifiers())
                    && f.getType() == cls)
                {
                    Object instance = f.get(null);
                    String name = (String)getName.invoke(instance);

                    Object resolved = null;
                    try
                    {
                        resolved = fromName.invoke(null, name);
                    }
                    catch (InvocationTargetException e)
                    {
                        // some specs throw rather than return null on an unknown name;
                        // either way the round-trip failed, recorded below as "null".
                    }

                    checked++;
                    if (resolved != instance)
                    {
                        failures.append("\n  ").append(cls.getSimpleName()).append('.').append(f.getName())
                            .append(": fromName(\"").append(name).append("\") -> ")
                            .append(resolved == null ? "null" : "a different instance");
                    }
                }
            }
        }

        if (failures.length() != 0)
        {
            fail("fromName(getName()) did not round-trip for:" + failures);
        }

        // sanity: the reflection actually exercised the specs rather than silently finding none.
        assertTrue("expected to check many parameter sets, only saw " + checked, checked > 100);
    }

    /**
     * Drives the reachable path: a generated key's {@code getParameterSpec()} must be non-null and
     * its {@code getName()} must not NPE, for each spec class fixed here.
     */
    public void testGeneratedKeyParameterSpec()
        throws Exception
    {
        assertReachableParameterSpec("SABER", SABERParameterSpec.lightsaberkem128r3, "lightsaberkem128r3");
        assertReachableParameterSpec("HQC", HQCParameterSpec.hqc128, "hqc-128");
        assertReachableParameterSpec("Snova", SnovaParameterSpec.SNOVA_24_5_4_SSK, "SNOVA_24_5_4_SSK");
    }

    private void assertReachableParameterSpec(String algorithm, AlgorithmParameterSpec spec, String expectedName)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "BCPQC");
        kpg.initialize(spec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        assertParameterSpecName(algorithm + " public key", kp.getPublic(), expectedName);
        assertParameterSpecName(algorithm + " private key", kp.getPrivate(), expectedName);
    }

    // Equivalent to ((XxxKey)key).getParameterSpec().getName(), without binding to each
    // interface type: getParameterSpec() is the public method backing the *Key interfaces.
    private void assertParameterSpecName(String what, Key key, String expectedName)
        throws Exception
    {
        Object spec = key.getClass().getMethod("getParameterSpec").invoke(key);
        assertNotNull(what + ".getParameterSpec() returned null", spec);

        String name = (String)spec.getClass().getMethod("getName").invoke(spec);
        assertEquals(what + ".getParameterSpec().getName()", expectedName, name);
    }
}
