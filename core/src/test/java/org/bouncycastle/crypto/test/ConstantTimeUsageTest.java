package org.bouncycastle.crypto.test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Checks that the code paths handling a secret scalar still reach for BouncyCastle's hardened
 * arithmetic rather than the variable-time defaults.
 * <p>
 * The substitutions guarded here - BigInteger.modInverse to BigIntegers.modOddInverse,
 * add(...).mod(...) to BigIntegers.modAdd, and the default point multiplier to the secure one -
 * all preserve the result, so no functional test can tell whether they are in place: the KAT
 * vectors and the round-trips pass either way, which is exactly why the substitutions can be
 * undone by an unrelated edit without anything going red. What is left to look at is the compiled
 * form, so this test reads each class file back and checks the symbols its constant pool must and
 * must not contain.
 * </p><p>
 * Note what this does and does not establish. It says a named call is still being made; it says
 * nothing about whether the surrounding code is constant time, and it cannot see a secret that
 * reaches a variable-time operation by some other route. It is a regression gate for four specific
 * call sites, not a proof.
 * </p><p>
 * A scan that quietly reads nothing would pass every "must not contain" check, so the controls in
 * {@link #checkControls()} are load bearing: they run the same scan over a class in this file that
 * deliberately calls BigInteger.modInverse, and fail if it is not flagged.
 * </p>
 */
public class ConstantTimeUsageTest
    extends SimpleTest
{
    private static final String REQUIRED = "required";
    private static final String FORBIDDEN = "forbidden";

    /**
     * Rows of {class file, symbol, REQUIRED or FORBIDDEN}. The reason each secret is worth
     * protecting is recorded at the call site itself.
     */
    private static final String[][] RULES =
    {
        // RFC 6508 sec. 6.1.1 receiver secret key, [(a + z)^-1]P with z the KMS master secret
        {"org/bouncycastle/crypto/kems/SAKKEKEMExtractor", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/kems/SAKKEKEMExtractor", "modOddInverse", REQUIRED},
        {"org/bouncycastle/crypto/kems/SAKKEKEMExtractor", "multiplySecret", REQUIRED},
        {"org/bouncycastle/crypto/kems/SAKKEKEMExtractor", "modInverse", FORBIDDEN},

        // RFC 6507 sec. 5.2.1 ECCSI signing, s' = ((HE + r * SSK)^-1 * j) mod q
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modOddInverse", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modInverse", FORBIDDEN},

        // GM/T 0044.2 signature user key, t1 = H1 + ks then t2 = ks * t1^-1, ds = [t2]P1 in G1
        {"org/bouncycastle/crypto/params/SM9SigMasterPrivateKeyParameters", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9SigMasterPrivateKeyParameters", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9SigMasterPrivateKeyParameters", "modOddInverse", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9SigMasterPrivateKeyParameters", "multiplySecure", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9SigMasterPrivateKeyParameters", "modInverse", FORBIDDEN},

        // GM/T 0044.4 encryption user key, de = [t2]P2 in G2. There is deliberately no
        // multiplySecure row: G2 has no constant-time multiplier, only the fixed-iteration ladder
        // in SM9G2Point.multiply, which that method's javadoc records as a hardening.
        {"org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters", "modOddInverse", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters", "modInverse", FORBIDDEN},
    };

    public String getName()
    {
        return "ConstantTimeUsage";
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != RULES.length; i++)
        {
            String name = RULES[i][0];
            String symbol = RULES[i][1];
            boolean present = contains(readClassFile(name), symbol);

            if (REQUIRED.equals(RULES[i][2]))
            {
                if (!present)
                {
                    fail(name + " no longer references " + symbol
                        + " - a secret value may have moved back onto a variable-time path");
                }
            }
            else if (present)
            {
                fail(name + " references the variable-time " + symbol
                    + " - use the constant-time equivalent in BigIntegers instead");
            }
        }

        checkControls();
    }

    /**
     * The scan has to be able to fail. {@link LeakyControl} calls BigInteger.modInverse, so a scan
     * that is working flags it; one that reads nothing - a resource that cannot be found, a symbol
     * encoded differently from what {@link #contains(byte[], String)} looks for - does not, and
     * every FORBIDDEN rule above would then pass without a byte having been examined. The second
     * check is the other half: a matcher that always says yes would pass the first.
     */
    private void checkControls()
        throws IOException
    {
        String control = "org/bouncycastle/crypto/test/ConstantTimeUsageTest$LeakyControl";
        byte[] bytes = readClassFile(control);

        if (!contains(bytes, "modInverse"))
        {
            fail("the scan did not find BigInteger.modInverse in " + control
                + ", so it cannot be trusted to have found nothing elsewhere");
        }
        if (contains(bytes, "modOddInverse"))
        {
            fail("the scan reported a symbol " + control + " does not reference");
        }
        if (!LeakyControl.invert(BigInteger.valueOf(3), BigInteger.valueOf(11)).equals(BigInteger.valueOf(4)))
        {
            fail("positive control did not compute an inverse");
        }
    }

    private byte[] readClassFile(String name)
        throws IOException
    {
        InputStream in = getClass().getResourceAsStream("/" + name + ".class");
        if (in == null)
        {
            fail("unable to read the class file for " + name + " - the check cannot run");
            return null;
        }

        try
        {
            return Streams.readAll(in);
        }
        finally
        {
            in.close();
        }
    }

    /**
     * True if the class file references the given symbol. A method name appears in the constant
     * pool as plain UTF-8, so a byte scan finds it without having to parse the pool; the symbols
     * used here are long enough not to collide with anything else the file carries, and note that
     * "modOddInverse" does not contain "modInverse" as a substring, which is what lets the two be
     * required and forbidden in the same class.
     */
    private static boolean contains(byte[] data, String symbol)
    {
        byte[] needle = Strings.toByteArray(symbol);

        for (int i = 0; i <= data.length - needle.length; i++)
        {
            int j = 0;
            while (j != needle.length && data[i + j] == needle[j])
            {
                ++j;
            }
            if (j == needle.length)
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Deliberately variable time. This exists only as the positive control for the scan above and
     * nothing else should call it.
     */
    private static class LeakyControl
    {
        static BigInteger invert(BigInteger x, BigInteger m)
        {
            return x.modInverse(m);
        }
    }

    public static void main(String[] args)
    {
        runTest(new ConstantTimeUsageTest());
    }
}
