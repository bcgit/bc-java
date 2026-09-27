package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.test.SimpleTest;

/**
 * KeyAgreement.init() declares InvalidKeyException and InvalidAlgorithmParameterException, so an
 * initialisation it cannot carry out has to be reported as one of those.
 * <p>
 * The unified agreements (ECCDHU, DHU, X25519U/X448U) take the ephemeral half of the agreement from
 * a DHUParameterSpec, and the MQV agreements from an MQVParameterSpec. Given anything else - a plain
 * UserKeyingMaterialSpec, or no spec at all - ECMQV reported it, while the three unified families
 * carried the wrong object into the agreement instead: the EC and XDH ones threw ClassCastException
 * from the cast that follows, and the DH one accepted the initialisation and then threw
 * NullPointerException from doPhase, where the absent spec is read back.
 * </p><p>
 * The VKO agreements are the other side of the same coin: RFC 7836 sec. 4.3 makes the UKM optional
 * with the value 1, but initialising without a UserKeyingMaterialSpec put a null where the UKM
 * belongs and threw NullPointerException.
 * </p>
 */
public class KeyAgreementInitParametersTest
    extends SimpleTest
{
    private static final byte[] UKM = new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 };

    public String getName()
    {
        return "KeyAgreementInitParameters";
    }

    public void performTest()
        throws Exception
    {
        KeyPair ecKey = generate("EC", new ECNamedCurveGenParameterSpec("P-256"));
        KeyPair dhKey = generate("DH", null);
        KeyPair xKey = generate("X25519", null);
        KeyPair gostKey = generate("ECGOST3410-2012", new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));

        // the ephemeral half only arrives with the right spec - anything else is a parameter error
        checkRejectsPlainUKM("ECCDHUwithSHA256KDF", ecKey);
        checkRejectsPlainUKM("ECMQVwithSHA256KDF", ecKey);
        checkRejectsPlainUKM("DHUwithSHA256KDF", dhKey);
        checkRejectsPlainUKM("MQVwithSHA256KDF", dhKey);
        checkRejectsPlainUKM("X25519UwithSHA256KDF", xKey);

        checkRejectsNoSpec("ECCDHUwithSHA256KDF", ecKey);
        checkRejectsNoSpec("ECMQVwithSHA256KDF", ecKey);
        checkRejectsNoSpec("DHUwithSHA256KDF", dhKey);
        checkRejectsNoSpec("MQVwithSHA256KDF", dhKey);
        checkRejectsNoSpec("X25519UwithSHA256KDF", xKey);

        checkVKODefaultUKM(gostKey);
        checkUKMReachesTheKDF(ecKey, xKey);

        // only an HKDF based agreement has a use for a KDF salt - anything else would drop it silently
        checkRejectsSalt("ECDHwithSHA256KDF", ecKey);
        checkRejectsSalt("ECCDHwithSHA256KDF", ecKey);
        checkRejectsSalt("ECCDHwithSHA256CKDF", ecKey);
        checkRejectsSalt("DHwithSHA256KDF", dhKey);
        checkRejectsSalt("X25519withSHA256KDF", xKey);
        checkRejectsSalt("X25519withSHA256CKDF", xKey);
        checkRejectsSalt("ECGOST3410-2012-256", gostKey);

        checkAcceptsSalt("X25519withSHA256HKDF", xKey);
        checkAcceptsSalt("XDHwithSHA256HKDF", xKey);
        checkAcceptsSalt("ECDHwithSHA256HKDF", ecKey);

        checkNoUkm(ecKey, xKey);

        checkEmulateOracle(xKey, generate("X448", null));
    }

    /**
     * Properties.EMULATE_ORACLE makes the XDH agreements report themselves as "XDH", and the SPI
     * used to take that name for the algorithm too: the unified agreements lost the DHU requirement
     * (refusing a DHUParameterSpec, running a plain agreement without one) and the curve specific
     * ones accepted a key on the other curve. The name is only for messages.
     */
    private void checkEmulateOracle(KeyPair xKey, KeyPair x448Key)
        throws Exception
    {
        Properties.setThreadOverride(Properties.EMULATE_ORACLE, true);
        try
        {
            checkRejectsPlainUKM("X25519UwithSHA256KDF", xKey);
            checkRejectsPlainUKM("X448UwithSHA512KDF", x448Key);
            checkRejectsNoSpec("X25519UwithSHA256KDF", xKey);
            checkRejectsNoSpec("X448UwithSHA512KDF", x448Key);

            checkRejectsOtherCurve("X25519", x448Key);
            checkRejectsOtherCurve("X25519withSHA256KDF", x448Key);
            checkRejectsOtherCurve("X448", xKey);
            checkRejectsOtherCurve("X448withSHA512KDF", xKey);

            checkUnifiedAgreement("X25519UwithSHA256KDF", xKey, generate("X25519", null));
            checkUnifiedAgreement("X448UwithSHA512KDF", x448Key, generate("X448", null));

            // the XDH names are not tied to a curve
            KeyAgreement agreement = agreement("XDH");
            if (agreement != null)
            {
                agreement.init(xKey.getPrivate());
                agreement.init(x448Key.getPrivate());
            }
        }
        finally
        {
            Properties.removeThreadOverride(Properties.EMULATE_ORACLE);
        }
    }

    private void checkRejectsOtherCurve(String algorithm, KeyPair kp)
        throws Exception
    {
        KeyAgreement agreement = agreement(algorithm);
        if (agreement == null)
        {
            return;
        }

        try
        {
            agreement.init(kp.getPrivate());

            fail(algorithm + " accepted a key on the other curve");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
    }

    private void checkUnifiedAgreement(String algorithm, KeyPair kp, KeyPair other)
        throws Exception
    {
        String keyAlg = algorithm.startsWith("X448") ? "X448" : "X25519";
        KeyPair ephemeral = generate(keyAlg, null);
        KeyPair otherEphemeral = generate(keyAlg, null);

        KeyAgreement a = agreement(algorithm);
        KeyAgreement b = agreement(algorithm);
        if (a == null)
        {
            return;
        }

        a.init(kp.getPrivate(), new DHUParameterSpec(ephemeral, otherEphemeral.getPublic(), UKM));
        b.init(other.getPrivate(), new DHUParameterSpec(otherEphemeral, ephemeral.getPublic(), UKM));
        a.doPhase(other.getPublic(), true);
        b.doPhase(kp.getPublic(), true);

        isTrue(algorithm + " unified agreement did not agree",
            Arrays.areEqual(a.generateSecret("AES[256]").getEncoded(), b.generateSecret("AES[256]").getEncoded()));
    }

    /**
     * A KDF based agreement given no user keying material has to derive what it does with an empty
     * one. ConcatenationKDFGenerator threw NullPointerException for a missing OtherInfo, so each
     * concatenation KDF agreement below failed that way unless the caller supplied some - the XDH
     * one only escaped because its SPI substituted an empty value itself.
     */
    private void checkNoUkm(KeyPair ecKey, KeyPair xKey)
        throws Exception
    {
        byte[] empty = new byte[0];

        KeyPair ecOther = generate("EC", new ECNamedCurveGenParameterSpec("P-256"));
        KeyPair ecEphem = generate("EC", new ECNamedCurveGenParameterSpec("P-256"));
        KeyPair ecOtherEphem = generate("EC", new ECNamedCurveGenParameterSpec("P-256"));

        // MQV needs the subgroup order, so use a group that carries q
        DHDomainParameterSpec dhGroup = new DHDomainParameterSpec(DHStandardGroups.rfc7919_ffdhe2048);
        KeyPair dhKey = generate("DH", dhGroup);
        KeyPair dhOther = generate("DH", dhGroup);
        KeyPair dhEphem = generate("DH", dhGroup);
        KeyPair dhOtherEphem = generate("DH", dhGroup);

        KeyPair xOther = generate("X25519", null);

        checkNoUkm("ECCDHwithSHA256CKDF", ecKey, ecOther, null, new UserKeyingMaterialSpec(empty));
        checkNoUkm("X25519withSHA256CKDF", xKey, xOther, null, new UserKeyingMaterialSpec(empty));

        checkNoUkm("ECCDHUwithSHA256CKDF", ecKey, ecOther,
            new DHUParameterSpec(ecEphem, ecOtherEphem.getPublic()),
            new DHUParameterSpec(ecEphem, ecOtherEphem.getPublic(), empty));
        checkNoUkm("ECMQVwithSHA256CKDF", ecKey, ecOther,
            new MQVParameterSpec(ecEphem, ecOtherEphem.getPublic()),
            new MQVParameterSpec(ecEphem, ecOtherEphem.getPublic(), empty));
        checkNoUkm("DHUwithSHA256CKDF", dhKey, dhOther,
            new DHUParameterSpec(dhEphem, dhOtherEphem.getPublic()),
            new DHUParameterSpec(dhEphem, dhOtherEphem.getPublic(), empty));
        checkNoUkm("MQVwithSHA256CKDF", dhKey, dhOther,
            new MQVParameterSpec(dhEphem, dhOtherEphem.getPublic()),
            new MQVParameterSpec(dhEphem, dhOtherEphem.getPublic(), empty));
    }

    private void checkNoUkm(String algorithm, KeyPair kp, KeyPair other, AlgorithmParameterSpec noUkm,
        AlgorithmParameterSpec emptyUkm)
        throws Exception
    {
        if (agreement(algorithm) == null)
        {
            return;
        }

        byte[] withNone = deriveWith(algorithm, kp, other, noUkm);
        byte[] withEmpty = deriveWith(algorithm, kp, other, emptyUkm);

        isTrue(algorithm + " without user keying material differs from an empty one",
            Arrays.areEqual(withNone, withEmpty));
    }

    private byte[] deriveWith(String algorithm, KeyPair a, KeyPair b, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyAgreement agreement = KeyAgreement.getInstance(algorithm, "BC");

        if (spec == null)
        {
            agreement.init(a.getPrivate());
        }
        else
        {
            agreement.init(a.getPrivate(), spec);
        }

        agreement.doPhase(b.getPublic(), true);

        return agreement.generateSecret("AES").getEncoded();
    }

    private void checkRejectsSalt(String algorithm, KeyPair kp)
        throws Exception
    {
        KeyAgreement agreement = agreement(algorithm);
        if (agreement == null)
        {
            return;
        }

        try
        {
            agreement.init(kp.getPrivate(), new UserKeyingMaterialSpec(UKM, UKM));

            fail(algorithm + " accepted a KDF salt it does not use");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue(algorithm + ": " + e.getMessage(), e.getMessage().endsWith(" key agreement does not use a KDF salt"));
        }

        // the same spec without the salt is still fine
        agreement.init(kp.getPrivate(), new UserKeyingMaterialSpec(UKM));
    }

    private void checkAcceptsSalt(String algorithm, KeyPair kp)
        throws Exception
    {
        KeyAgreement agreement = agreement(algorithm);
        if (agreement == null)
        {
            return;
        }

        agreement.init(kp.getPrivate(), new UserKeyingMaterialSpec(UKM, UKM));
    }

    private void checkRejectsPlainUKM(String algorithm, KeyPair kp)
        throws Exception
    {
        KeyAgreement agreement = agreement(algorithm);
        if (agreement == null)
        {
            return;
        }

        try
        {
            agreement.init(kp.getPrivate(), new UserKeyingMaterialSpec(UKM));

            fail(algorithm + " accepted a UserKeyingMaterialSpec in place of its own spec");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // expected
        }
    }

    private void checkRejectsNoSpec(String algorithm, KeyPair kp)
        throws Exception
    {
        KeyAgreement agreement = agreement(algorithm);
        if (agreement == null)
        {
            return;
        }

        try
        {
            agreement.init(kp.getPrivate());

            fail(algorithm + " accepted an initialisation with no spec at all");
        }
        catch (InvalidKeyException e)
        {
            // expected
        }
    }

    /**
     * RFC 7836 sec. 4.3: the UKM is optional for VKO and takes the value 1 when it is absent.
     */
    private void checkVKODefaultUKM(KeyPair kp)
        throws Exception
    {
        KeyAgreement agreement = agreement("ECGOST3410-2012-256");
        if (agreement == null)
        {
            return;
        }

        KeyPair other = generate("ECGOST3410-2012", new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));

        byte[] withoutSpec = deriveVKO(kp, other, null);
        byte[] withOne = deriveVKO(kp, other, new byte[]{ 1 });
        byte[] withTwo = deriveVKO(kp, other, new byte[]{ 2 });

        isTrue("VKO without a UKM does not use the RFC 7836 default of 1",
            Arrays.areEqual(withoutSpec, withOne));
        isTrue("VKO derived the same key for two different UKMs",
            !Arrays.areEqual(withOne, withTwo));
    }

    /**
     * A UKM that does not reach the key derivation function would leave the derived key unchanged.
     */
    private void checkUKMReachesTheKDF(KeyPair ecKey, KeyPair xKey)
        throws Exception
    {
        String[] algorithms = new String[]{ "ECDHwithSHA256KDF", "ECCDHwithSHA256KDF", "ECDHwithSHA256HKDF",
            "X25519withSHA256KDF", "X25519withSHA256HKDF" };
        KeyPair[] keys = new KeyPair[]{ ecKey, ecKey, ecKey, xKey, xKey };

        for (int i = 0; i != algorithms.length; i++)
        {
            if (agreement(algorithms[i]) == null)
            {
                continue;
            }

            KeyPair other = (keys[i] == ecKey)
                ? generate("EC", new ECNamedCurveGenParameterSpec("P-256"))
                : generate("X25519", null);

            byte[] first = derive(algorithms[i], keys[i], other, UKM);
            byte[] second = derive(algorithms[i], keys[i], other, new byte[]{ 9, 9, 9, 9, 9, 9, 9, 9 });

            isTrue(algorithms[i] + " derived the same key for two different UKMs",
                !Arrays.areEqual(first, second));
        }
    }

    private byte[] deriveVKO(KeyPair a, KeyPair b, byte[] ukm)
        throws Exception
    {
        KeyAgreement agreement = KeyAgreement.getInstance("ECGOST3410-2012-256", "BC");

        if (ukm == null)
        {
            agreement.init(a.getPrivate());
        }
        else
        {
            agreement.init(a.getPrivate(), new UserKeyingMaterialSpec(ukm));
        }

        agreement.doPhase(b.getPublic(), true);

        return agreement.generateSecret("AES").getEncoded();
    }

    private byte[] derive(String algorithm, KeyPair a, KeyPair b, byte[] ukm)
        throws Exception
    {
        KeyAgreement agreement = KeyAgreement.getInstance(algorithm, "BC");

        agreement.init(a.getPrivate(), new UserKeyingMaterialSpec(ukm));
        agreement.doPhase(b.getPublic(), true);

        return agreement.generateSecret("AES").getEncoded();
    }

    private KeyAgreement agreement(String algorithm)
        throws Exception
    {
        try
        {
            return KeyAgreement.getInstance(algorithm, "BC");
        }
        catch (NoSuchAlgorithmException e)
        {
            return null;        // not in this distribution
        }
    }

    private KeyPair generate(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        if (spec != null)
        {
            kpGen.initialize(spec);
        }
        else if (algorithm.equals("DH"))
        {
            kpGen.initialize(2048);
        }

        return kpGen.generateKeyPair();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyAgreementInitParametersTest());
    }
}
