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
 * reaches a variable-time operation by some other route. It is a regression gate for the call
 * sites the table names, not a proof, and it works a class at a time: where a class makes the same
 * call more than once, reverting one of them leaves the symbol in the constant pool and the row
 * satisfied.
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

        // RFC 6508 sec. 6.1 KMS master secret z, used as Z = [z]P when a key is constructed or
        // generated. No FORBIDDEN row for the default multiplier is possible: its name is a
        // substring of multiplySecret, so the byte scan cannot tell the two apart.
        {"org/bouncycastle/crypto/params/SAKKEPrivateKeyParameters", "multiplySecret", REQUIRED},

        // RFC 6507 sec. 5.2.1 ECCSI signing, s' = ((HE + r * SSK)^-1 * j) mod q; the nonce j and
        // the long-term SSK also each scale G, kept off the curve's default multiplier the same
        // way as the SAKKE secrets above.
        {"org/bouncycastle/crypto/signers/ECCSISigner", "multiplySecret", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modOddInverse", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECCSISigner", "modInverse", FORBIDDEN},

        // GM/T 0044.2 / 0044.4 user keys, t1 = H1 + s then t2 = s * t1^-1 over the KGC's master
        // secret s, formed for both key families by the one helper
        {"org/bouncycastle/crypto/params/SM9KeyDerivation", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9KeyDerivation", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9KeyDerivation", "modOddInverse", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9KeyDerivation", "modInverse", FORBIDDEN},

        // GM/T 0044.2 signature user key ds = [t2]P1 in G1
        {"org/bouncycastle/crypto/params/SM9SigMasterPrivateKeyParameters", "multiplySecure", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9SigMasterPrivateKeyParameters", "modInverse", FORBIDDEN},

        // ... which the key's own class neither pairs nor multiplies: multiPair, which evaluates the
        // Miller loop's lines at its G1 points as they are and randomises nothing, and multiplyPublic,
        // the GLV method, whose steps and reads depend on its scalar and its point, and which keeps the
        // point's image with the point, are for public values, and neither may take the key.
        {"org/bouncycastle/crypto/params/SM9SigPrivateKeyParameters", "multiPair", FORBIDDEN},
        {"org/bouncycastle/crypto/params/SM9SigPrivateKeyParameters", "multiplyPublic", FORBIDDEN},

        // GM/T 0044.4 encryption user key, de = [t2]P2 in G2, and the master public key
        // P_pub-e = [ke]P1 in G1, formed from the master secret whenever a master key is generated
        // or decoded. The multiplySecure row is the second of these: G2's multiplication is
        // SM9G2Point.multiply, a comb for P2 and a ladder for any other point, whose hardenings that
        // method's javadoc records.
        {"org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters", "multiplySecure", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters", "modInverse", FORBIDDEN},

        // GM/T 0044.2 signing, w = g^r and l = (r - h) mod N over the secret nonce against an h
        // that travels in the signature, then S = [l]ds over the user's signing key. No modInverse
        // row: the signer has no inversion to do.
        {"org/bouncycastle/crypto/signers/SM9Signer", "powSecure", REQUIRED},
        {"org/bouncycastle/crypto/signers/SM9Signer", "modSubtract", REQUIRED},
        {"org/bouncycastle/crypto/signers/SM9Signer", "multiplySecure", REQUIRED},

        // GM/T 0044.4 public-key encryption and key encapsulation, C1 = [r]Q_B and w = g^r over the
        // ephemeral r, from which K - and with it the message or the encapsulated key - follows.
        // C1 is formed by the master public key's multiplyRecipientPoint, whose own rows follow the
        // key exchange's. As for the signer there is no FORBIDDEN row for the default forms: G1's
        // multiply and Fp12's pow are substrings of multiplyRecipientPoint and powSecure.
        {"org/bouncycastle/crypto/engines/SM9Engine", "multiplyRecipientPoint", REQUIRED},
        {"org/bouncycastle/crypto/engines/SM9Engine", "powSecure", REQUIRED},
        // GM/T 0044.4 7.2.1 B5, the received C3 against the MAC the recipient's key derives: a
        // compare that stops at the first differing byte reports how much of a C3 was right. The
        // engine compares nothing else, so the variable-time form is forbidden outright.
        {"org/bouncycastle/crypto/engines/SM9Engine", "constantTimeAreEqual", REQUIRED},
        {"org/bouncycastle/crypto/engines/SM9Engine", "areEqual", FORBIDDEN},
        {"org/bouncycastle/crypto/kems/SM9KEMGenerator", "multiplyRecipientPoint", REQUIRED},
        {"org/bouncycastle/crypto/kems/SM9KEMGenerator", "powSecure", REQUIRED},

        // GM/T 0044.3 key exchange, R = [r]Q_peer and the powers of e(P_pub-e, P2) and of the
        // pairing the shared key is derived from, all over the ephemeral r. The class raises to r
        // four times and the per-class scan is satisfied by any one of them;
        // SM9KeyExchangeTest.checkSecretPowersDraw holds each party's two to the draws of
        // powSecureFixedBase and powSecure.
        {"org/bouncycastle/crypto/agreement/SM9KeyExchange", "multiplyRecipientPoint", REQUIRED},
        {"org/bouncycastle/crypto/agreement/SM9KeyExchange", "powSecure", REQUIRED},

        // ... [r]Q_B and [r]Q_peer, which the three form through the master public key's
        // multiplyRecipientPoint as [r h1]P1 + [r]P_pub-e: the product r h1 mod N by modMult, which
        // runs the same steps whatever r is, and the sum by SM9Curve.sumOfTwoMultipliesSecure, the
        // comb over the tables of both points. (recipientPoint, beside it, multiplies P1 by the
        // public h1 alone.)
        {"org/bouncycastle/crypto/params/SM9EncMasterPublicKeyParameters", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/params/SM9EncMasterPublicKeyParameters", "sumOfTwoMultipliesSecure", REQUIRED},
        // SM9Curve.multiplyPublic, the GLV method verification multiplies the signature's S by,
        // takes steps and reads multiples that depend on its scalar and its point, and is for public
        // values only: none of the classes that multiply a point by an ephemeral may reach it.
        {"org/bouncycastle/crypto/engines/SM9Engine", "multiplyPublic", FORBIDDEN},
        {"org/bouncycastle/crypto/kems/SM9KEMGenerator", "multiplyPublic", FORBIDDEN},
        {"org/bouncycastle/crypto/agreement/SM9KeyExchange", "multiplyPublic", FORBIDDEN},
        {"org/bouncycastle/crypto/params/SM9EncMasterPublicKeyParameters", "multiplyPublic", FORBIDDEN},
        // SM9Pairing.multiPair, which forms verification's product of pairings and the pairing value
        // a master public key fixes, is for public values only as well: it computes the lines of
        // each G2 point's Miller loop from the point as it is and keeps them with the point, and its
        // final exponentiation takes no random factor. The user's encryption key de is a G2 point,
        // and the four classes that pair it - decryption, decapsulation, the key exchange, and the
        // import that checks a key against its master public key - do so through
        // SM9Pairing.pairing, which starts from a random representative of de on every call and
        // gives the value its final exponentiation runs on a random factor. multiPair returns the
        // same value, so no round trip or vector tells the two apart - only for the key exchange
        // does a test see the difference, in the number of draws SM9KeyExchangeTest holds
        // calculateKey to - while de's lines would carry no random factor and would stay with the
        // key: none of the four may reach it.
        {"org/bouncycastle/crypto/engines/SM9Engine", "multiPair", FORBIDDEN},
        {"org/bouncycastle/crypto/kems/SM9KEMExtractor", "multiPair", FORBIDDEN},
        {"org/bouncycastle/crypto/agreement/SM9KeyExchange", "multiPair", FORBIDDEN},
        {"org/bouncycastle/crypto/params/SM9EncPrivateKeyParameters", "multiPair", FORBIDDEN},

        // The SM9 math layer, which the rows above do not reach although it is where the key is
        // consumed. Its F_q arithmetic is Fp's, on fixed-width limbs, and the one inversion in the
        // tower is Fp's call of the constant-time Mod.checkedModOddInverse, where the tower had inverted
        // with BigInteger.modInverse behind a random blinding factor: Fp2, which still blinds the
        // norm it inverts, and Fp12, which divides out powSecure's random factor, now reach it
        // through Fp, and neither may return to modInverse. Fp12.powSecureFixedBase, the comb for the
        // pairing values a master public key fixes, blinds the secret exponent with a random
        // multiple of the group order before it runs, or the running time reports the exponent's
        // bit length, and Fp12.powSecure, which splits its exponent into four through the
        // Frobenius, a split such a multiple would not change, blinds the split with random
        // multiples of vectors that stand for 0; both draw the random factor their running values
        // carry. SM9Curve.blind draws the multiple, for powSecureFixedBase and for
        // SM9G2Point.multiply, which blinds
        // its scalar - the KGC's secret when it derives [ks]P2 and [t2]P2 - and draws the factor its
        // comb for P2 carries the table's entries by, or starts its ladder from a random
        // representative of the point, as isInSubgroup starts its chain for a decoded key; and
        // SM9Pairing starts its Miller loop from a random representative of the G2 point it is
        // given, the user's private key on the decryption, KEM and key-exchange paths, and gives the
        // value its final exponentiation runs on a random factor, a power of a base it keeps by an
        // exponent it draws for the call. The draws are the randomisation, so the REQUIRED rows name
        // them. None of the three branches on its secret's bits: powSecure and powSecureFixedBase
        // read each column's entry out of their tables in full, as the pairing's comb reads each of
        // its own, through Fp12.lookup, the G2 comb
        // reads each of its own through SM9G2Point.lookup, the same full scan, and the G2 ladder
        // exchanges its running points at each bit by Fp's masked swap, both reading the blinded
        // scalar's bits from its words rather than through BigInteger.testBit. Each of those four
        // tables' scans starts at an entry drawn for it, so that the one step of the scan that moves
        // the entry read into place does not give away which it is: the nextBytes rows name that
        // draw in Fp12, which draws powSecure's blinding through it as well, and SM9G2Point, which
        // draws nothing else through it, and SM9KeyExchangeTest counts the pairing's, whose class
        // draws its random factor's exponent through it as well.
        // (Fp12 has no row for blind: the name of the local holding the blinded exponent would
        // satisfy it; nor a FORBIDDEN one for testBit, which its pow over public exponents calls;
        // nor Fp2 one for its blinding draw, whose names its own randomNonZero also calls -
        // SM9SignerTest counts that draw instead.)
        {"org/bouncycastle/math/ec/sm9/Fp", "checkedModOddInverse", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/Fp", "modInverse", FORBIDDEN},
        {"org/bouncycastle/math/ec/sm9/Fp2", "modInverse", FORBIDDEN},
        {"org/bouncycastle/math/ec/sm9/Fp12", "getSecureRandom", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/Fp12", "nextBytes", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/Fp12", "cmov", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/Fp12", "modInverse", FORBIDDEN},
        {"org/bouncycastle/math/ec/sm9/SM9Curve", "getSecureRandom", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G2Point", "blind", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G2Point", "randomNonZero", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G2Point", "nextBytes", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G2Point", "cswap", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G2Point", "testBit", FORBIDDEN},
        {"org/bouncycastle/math/ec/sm9/SM9Pairing", "randomNonZero", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9Pairing", "getSecureRandom", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9Pairing", "lookup", REQUIRED},
        // SM9Curve runs a secret multiplication in G1 through SM9G1Multiplier's comb, for P1, a signing
        // key ds and an encryption master public key P_pub-e, each of which keeps the table the comb
        // makes for it - run over the tables of P1 and P_pub-e at once for the [r h1]P1 + [r]P_pub-e
        // encryption, encapsulation and the key exchange send. It blinds the scalar with a random
        // multiple of N, carries the entries it reads by a random factor drawn for the call and reads
        // each entry through a full scan of the table from an entry drawn for it: the draws are the
        // randomisation, so the REQUIRED rows name them, and it does not read the blinded scalar's bits
        // through BigInteger.testBit. BouncyCastle's comb and fixed-window multiplier, which SM9Curve
        // ran before and which read the scalar's own digits from entries the same for every call, give
        // the same points, as the default multiplier does, so only these rows see a return to one of
        // them; no FORBIDDEN row can name the default, since ECPoint.multiply is a substring of
        // multiplySecure.
        {"org/bouncycastle/math/ec/sm9/SM9Curve", "SM9G1Multiplier", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9Curve", "FixedPointCombMultiplier", FORBIDDEN},
        {"org/bouncycastle/math/ec/sm9/SM9Curve", "ECConstantTimeMultiplier", FORBIDDEN},
        {"org/bouncycastle/math/ec/sm9/SM9G1Multiplier", "blind", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G1Multiplier", "randomNonZero", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G1Multiplier", "nextBytes", REQUIRED},
        {"org/bouncycastle/math/ec/sm9/SM9G1Multiplier", "testBit", FORBIDDEN},
        // The field of G1, where the secret multiples are computed: the KGC's [t2]P1 and [ke]P1,
        // the signer's [l]ds, and the ephemeral's multiples of the recipient's or the peer's
        // point. It brings each sum, difference and product below q by a subtraction always made,
        // kept or discarded under a mask, where it had compared the result with q through
        // Nat256.gte and subtracted on the answer, and it inverts through
        // Mod.checkedModOddInverse, as SM2's field does.
        {"org/bouncycastle/math/ec/custom/gm/SM9P256V1Field", "checkedModOddInverse", REQUIRED},
        {"org/bouncycastle/math/ec/custom/gm/SM9P256V1Field", "modInverse", FORBIDDEN},
        {"org/bouncycastle/math/ec/custom/gm/SM9P256V1Field", "gte", FORBIDDEN},

        // SEC 1 sec. 4.1.3 ECDSA signing, s = k^-1 * (e + d * r) mod n, over the signing key d and
        // the nonce inverse. No modOddInverse row: verifySignature calls modOddInverseVar on the
        // public s, and the scan cannot tell that name from the one signing needs, since the
        // shorter is a substring of the longer.
        {"org/bouncycastle/crypto/signers/ECDSASigner", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECDSASigner", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECDSASigner", "modInverse", FORBIDDEN},

        // GM/T 0003.2 SM2 signing, s = (1 + d)^-1 * (k - r * d) mod n, over the same secrets
        {"org/bouncycastle/crypto/signers/SM2Signer", "modSubtract", REQUIRED},
        {"org/bouncycastle/crypto/signers/SM2Signer", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/signers/SM2Signer", "modOddInverse", REQUIRED},
        {"org/bouncycastle/crypto/signers/SM2Signer", "modInverse", FORBIDDEN},

        // ISO/IEC 15946-2 EC-NR signing, s = u - r * x mod n, over the signing key and the
        // ephemeral private value
        {"org/bouncycastle/crypto/signers/ECNRSigner", "modSubtract", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECNRSigner", "modMult", REQUIRED},

        // BIP-340 Schnorr signing, s = k + e * d mod n, over the nonce and the signing key -
        // both after the conditional negations that put them back in [1, n-1]
        {"org/bouncycastle/crypto/signers/BIP340Signer", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/BIP340Signer", "modMult", REQUIRED},

        // DSTU 4145 signing, s = r * d + e mod n, over the signing key and the ephemeral e
        {"org/bouncycastle/crypto/signers/DSTU4145Signer", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/DSTU4145Signer", "modMult", REQUIRED},

        // FIPS 186-4 DSA signing, s = k^-1 * (m + x * r) mod q. As with ECDSA there is no
        // modOddInverse row: verifySignature calls modOddInverseVar on the public s, and the
        // shorter name is a substring of the longer one.
        {"org/bouncycastle/crypto/signers/DSASigner", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/DSASigner", "modMult", REQUIRED},
        {"org/bouncycastle/crypto/signers/DSASigner", "modInverse", FORBIDDEN},

        // GOST R 34.10-94 signing, s = k * m + x * r mod q
        {"org/bouncycastle/crypto/signers/GOST3410Signer", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/GOST3410Signer", "modMult", REQUIRED},

        // GOST R 34.10-2001/2012 signing, s = k * e + d * r mod n. The nonce is redrawn until it
        // is below n, which the constant-time assembly requires - see ECGOST3410Test - so this
        // also guards the range check the draw depends on.
        {"org/bouncycastle/crypto/signers/ECGOST3410Signer", "modAdd", REQUIRED},
        {"org/bouncycastle/crypto/signers/ECGOST3410Signer", "modMult", REQUIRED},
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
                    + " - use its constant-time equivalent instead");
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
