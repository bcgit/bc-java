package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;

public class PGPv6KeyTest extends SimpleTest {

    // test vector from https://openpgp-wg.gitlab.io/rfc4880bis/#name-sample-v6-certificate-trans
    private static final String ARMORED_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n" +
            "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n" +
            "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n" +
            "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n" +
            "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n" +
            "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n" +
            "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n" +
            "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n" +
            "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    // test vector from https://openpgp-wg.gitlab.io/rfc4880bis/#name-sample-v6-secret-key-transf
    private static final String ARMORED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
            "k0mXubZvyl4GBg==\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final byte[] PRIMARY_FINGERPRINT = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
    private static final byte[] SUBKEY_FINGERPRINT = Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");

    @Override
    public void performTest() throws Exception {
        testFingerprintCalculation();
    }

    private void testFingerprintCalculation() throws IOException, PGPException {
        KeyFingerPrintCalculator bcFpCalc = new BcKeyFingerprintCalculator();
        testCertificateFingerprintCalculation(bcFpCalc);
        testKeyFingerprintCalculation(bcFpCalc);

        KeyFingerPrintCalculator jcaFpCalc = new JcaKeyFingerprintCalculator();
        testCertificateFingerprintCalculation(jcaFpCalc);
        testKeyFingerprintCalculation(jcaFpCalc);
    }

    private void testCertificateFingerprintCalculation(KeyFingerPrintCalculator fingerPrintCalculator) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_CERT.getBytes());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcIn = new BCPGInputStream(armorIn);

        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(bcIn, fingerPrintCalculator);

        Iterator<PGPPublicKey> it = publicKeys.getPublicKeys();
        PGPPublicKey key = it.next();
        isTrue(Arrays.areEqual(PRIMARY_FINGERPRINT, key.getFingerprint()));
        key = it.next();
        isTrue(Arrays.areEqual(SUBKEY_FINGERPRINT, key.getFingerprint()));
    }

    private void testKeyFingerprintCalculation(KeyFingerPrintCalculator fingerPrintCalculator)
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(ARMORED_KEY.getBytes());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        BCPGInputStream bcIn = new BCPGInputStream(armorIn);

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(bcIn, fingerPrintCalculator);

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey key = it.next();
        isTrue(Arrays.areEqual(PRIMARY_FINGERPRINT, key.getFingerprint()));
        key = it.next();
        isTrue(Arrays.areEqual(SUBKEY_FINGERPRINT, key.getFingerprint()));
    }

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }

    public static void main(String[] args) {
        runTest(new PGPv6KeyTest());
    }
}
