package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Arrays;
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
        String[] algorithms = new String[]{ "ECDHwithSHA256KDF", "ECCDHwithSHA256KDF", "X25519withSHA256KDF",
            "X25519withSHA256HKDF" };
        KeyPair[] keys = new KeyPair[]{ ecKey, ecKey, xKey, xKey };

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
