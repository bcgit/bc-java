package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class KeyIdentifierTest
        extends SimpleTest
{
    @Override
    public String getName()
    {
        return "KeyIdentifierTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testWildcardIdentifier();
        testWildcardMatches();
        testIdentifierFromKeyId();

        testIdentifierFromLongKeyId();

        testIdentifierFromV4Fingerprint();
        testIdentifierFromV6Fingerprint();

        testMatchV4Key();
        testMatchV6Key();
    }

    private void testWildcardIdentifier()
    {
        KeyIdentifier wildcard = KeyIdentifier.wildcard();
        isEquals("Wildcard KeyIdentifier MUST have key-id 0",
                0L, wildcard.getKeyId());
        isTrue("Wildcard KeyIdentifier MUST have zero-length fingerprint",
                Arrays.areEqual(new byte[0], wildcard.getFingerprint()));
        isTrue("Wildcard MUST return true for isWildcard()",
                wildcard.isWildcard());

        isEquals("*", wildcard.toString());

        KeyIdentifier id = new KeyIdentifier(0L);
        isTrue(id.isWildcard());
    }

    private void testWildcardMatches() {
        KeyIdentifier wildcard = KeyIdentifier.wildcard();
        KeyIdentifier nonWildcard = new KeyIdentifier(123L);

        isTrue(wildcard.matches(nonWildcard));
        isTrue(nonWildcard.matches(wildcard));

        isTrue(!wildcard.matchesExplicit(nonWildcard));
        isTrue(!nonWildcard.matchesExplicit(wildcard));
    }

    private void testIdentifierFromKeyId()
    {
        KeyIdentifier identifier = new KeyIdentifier(1234L);
        isEquals("Identifier key ID mismatch",
                1234L, identifier.getKeyId());
        isTrue("Identifier MUST return null for getFingerprint()",
                identifier.getFingerprint() == null);

        isEquals("1234", identifier.toString());
    }

    private void testIdentifierFromLongKeyId()
    {
        isEquals(5145070902336167606L, new KeyIdentifier("4766F6B9D5F21EB6").getKeyId());
        isEquals(5145070902336167606L, new KeyIdentifier("4766f6b9d5f21eb6").getKeyId());

        isEquals(5507497285755629956L, new KeyIdentifier("4C6E8F99F6E47184").getKeyId());
        isEquals(1745434690267590572L, new KeyIdentifier("1839079A640B2FAC").getKeyId());

        isTrue(new KeyIdentifier("1839079A640B2FAC").getFingerprint() == null);
    }

    private void testIdentifierFromV4Fingerprint()
    {
        String hexFingerprint = "D1A66E1A23B182C9980F788CFBFCC82A015E7330";
        byte[] fingerprint = Hex.decode(hexFingerprint);
        KeyIdentifier identifier = new KeyIdentifier(fingerprint);
        isTrue("Identifier fingerprint mismatch",
                Arrays.areEqual(fingerprint, identifier.getFingerprint()));
        isEquals("Identifier key-ID mismatch",
                FingerprintUtil.keyIdFromV4Fingerprint(fingerprint), identifier.getKeyId());

        isEquals(hexFingerprint, identifier.toString());
    }

    private void testIdentifierFromV6Fingerprint()
    {
        String hexFingerprint = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9";
        byte[] fingerprint = Hex.decode(hexFingerprint);
        KeyIdentifier identifier = new KeyIdentifier(fingerprint);
        isTrue("Identifier fingerprint mismatch",
                Arrays.areEqual(fingerprint, identifier.getFingerprint()));
        isEquals("Identifier key-ID mismatch",
                FingerprintUtil.keyIdFromV6Fingerprint(fingerprint), identifier.getKeyId());

        isEquals(hexFingerprint, identifier.toString());
    }

    private void testMatchV4Key()
            throws IOException, PGPException
    {
        PGPSecretKeyRing secretKeys = getV4Key();
        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)it.next();
        PGPSecretKey subkey = (PGPSecretKey)it.next();

        KeyIdentifier primaryIdentifier = primaryKey.getKeyIdentifier();
        isEquals(primaryKey.getKeyID(), primaryIdentifier.getKeyId());
        isTrue(Arrays.areEqual(primaryKey.getFingerprint(), primaryIdentifier.getFingerprint()));
        isTrue(primaryIdentifier.matches(primaryKey.getKeyIdentifier()));
        isTrue(primaryIdentifier.matches(primaryKey.getPublicKey().getKeyIdentifier()));
        isTrue(primaryKey.getPublicKey().getKeyIdentifier().getKeyId()==primaryIdentifier.getKeyId());
        isTrue(!primaryIdentifier.matches(subkey.getKeyIdentifier()));
        isTrue(!primaryIdentifier.matches(subkey.getPublicKey().getKeyIdentifier()));

        KeyIdentifier subkeyIdentifier = subkey.getKeyIdentifier();
        isEquals(subkey.getKeyID(), subkeyIdentifier.getKeyId());
        isTrue(Arrays.areEqual(subkey.getFingerprint(), subkeyIdentifier.getFingerprint()));
        isTrue(subkeyIdentifier.matches(subkey.getKeyIdentifier()));
        isTrue(subkeyIdentifier.matches(subkey.getPublicKey().getKeyIdentifier()));
        isTrue(!subkeyIdentifier.matches(primaryKey.getKeyIdentifier()));
        isTrue(!subkeyIdentifier.matches(primaryKey.getPublicKey().getKeyIdentifier()));

        PGPPrivateKey privateKey = primaryKey.extractPrivateKey(null);
        KeyIdentifier privateKeyIdentifier = privateKey.getKeyIdentifier(new JcaKeyFingerprintCalculator());
        isTrue(privateKeyIdentifier.matches(privateKey.getKeyIdentifier(new JcaKeyFingerprintCalculator())));
        isTrue(privateKeyIdentifier.matches(primaryKey.getKeyIdentifier()));
        isTrue(primaryIdentifier.matches(privateKey.getKeyIdentifier(new JcaKeyFingerprintCalculator())));
        isTrue(!subkeyIdentifier.matches(privateKey.getKeyIdentifier(new JcaKeyFingerprintCalculator())));

        KeyIdentifier noFingerPrintId = new KeyIdentifier(primaryKey.getKeyID());
        isTrue(primaryKey.getKeyIdentifier().matches(noFingerPrintId));

        KeyIdentifier wildcard = KeyIdentifier.wildcard();
        isTrue(wildcard.matches(primaryKey.getKeyIdentifier()));
        isTrue(wildcard.matches(subkey.getKeyIdentifier()));
        isTrue(wildcard.matches(privateKey.getKeyIdentifier(new JcaKeyFingerprintCalculator())));

        isTrue(primaryKey.getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
        isTrue(primaryKey.getPublicKey().getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
        isTrue(subkey.getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
        isTrue(subkey.getPublicKey().getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
    }

    private List<KeyIdentifier> asList(KeyIdentifier a, KeyIdentifier b)
    {
        List<KeyIdentifier> l = new ArrayList<KeyIdentifier>(2);

        l.add(a);
        l.add(b);

        return l;
    }

    private void testMatchV6Key()
            throws IOException, PGPException
    {
        PGPSecretKeyRing secretKeys = getV6Key();
        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)it.next();
        PGPSecretKey subkey = (PGPSecretKey)it.next();

        KeyIdentifier primaryIdentifier = primaryKey.getKeyIdentifier();
        isEquals(primaryKey.getKeyID(), primaryIdentifier.getKeyId());
        isTrue(Arrays.areEqual(primaryKey.getFingerprint(), primaryIdentifier.getFingerprint()));
        isTrue(primaryIdentifier.matches(primaryKey.getKeyIdentifier()));
        isTrue(primaryIdentifier.matches(primaryKey.getPublicKey().getKeyIdentifier()));
        isTrue(!primaryIdentifier.matches(subkey.getKeyIdentifier()));
        isTrue(!primaryIdentifier.matches(subkey.getPublicKey().getKeyIdentifier()));

        KeyIdentifier subkeyIdentifier = subkey.getKeyIdentifier();
        isEquals(subkey.getKeyID(), subkeyIdentifier.getKeyId());
        isTrue(Arrays.areEqual(subkey.getFingerprint(), subkeyIdentifier.getFingerprint()));
        isTrue(subkeyIdentifier.matches(subkey.getKeyIdentifier()));
        isTrue(subkeyIdentifier.matches(subkey.getPublicKey().getKeyIdentifier()));
        isTrue(!subkeyIdentifier.matches(primaryKey.getKeyIdentifier()));
        isTrue(!subkeyIdentifier.matches(primaryKey.getPublicKey().getKeyIdentifier()));

        PGPPrivateKey privateKey = primaryKey.extractPrivateKey(null);
        KeyIdentifier privateKeyIdentifier = privateKey.getKeyIdentifier(new BcKeyFingerprintCalculator());
        isTrue(privateKeyIdentifier.matches(privateKey.getKeyIdentifier(new BcKeyFingerprintCalculator())));
        isTrue(privateKeyIdentifier.matches(primaryKey.getKeyIdentifier()));
        isTrue(primaryIdentifier.matches(privateKey.getKeyIdentifier(new BcKeyFingerprintCalculator())));
        isTrue(!subkeyIdentifier.matches(privateKey.getKeyIdentifier(new BcKeyFingerprintCalculator())));

        KeyIdentifier noFingerPrintId = new KeyIdentifier(primaryKey.getKeyID());
        isTrue(primaryKey.getKeyIdentifier().matches(noFingerPrintId));

        KeyIdentifier wildcard = KeyIdentifier.wildcard();
        isTrue(wildcard.matches(primaryKey.getKeyIdentifier()));
        isTrue(wildcard.matches(subkey.getKeyIdentifier()));
        isTrue(wildcard.matches(privateKey.getKeyIdentifier(new BcKeyFingerprintCalculator())));

        isTrue(primaryKey.getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
        isTrue(primaryKey.getPublicKey().getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
        isTrue(subkey.getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
        isTrue(subkey.getPublicKey().getKeyIdentifier().isPresentIn(
                asList(primaryIdentifier, subkeyIdentifier)));
    }

    /**
     * Return the v6 test key from RFC9580.
     * Fingerprints:
     * <ul>
     *     <li>CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9</li>
     *     <li>12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885</li>
     * </ul>
     * @return test key
     * @throws IOException
     */
    private PGPSecretKeyRing getV6Key()
            throws IOException
    {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        return (PGPSecretKeyRing) objFac.nextObject();
    }

    /**
     * Return the 'Alice' test key.
     * Fingerprints:
     * <ul>
     *     <li>EB85BB5FA33A75E15E944E63F231550C4F47E38E</li>
     *     <li>EA02B24FFD4C1B96616D3DF24766F6B9D5F21EB6</li>
     * </ul>
     * @return Alice test key
     * @throws IOException
     */
    private PGPSecretKeyRing getV4Key()
            throws IOException
    {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: Alice's OpenPGP Transferable Secret Key\n" +
                "\n" +
                "lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
                "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj\n" +
                "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ\n" +
                "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
                "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
                "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB\n" +
                "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
                "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF\n" +
                "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
                "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
                "Pnn+We1aTBhaGa86AQ==\n" +
                "=n8OM\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        return (PGPSecretKeyRing) objFac.nextObject();
    }

    public static void main(String[] args)
    {
        runTest(new KeyIdentifierTest());
    }
}
