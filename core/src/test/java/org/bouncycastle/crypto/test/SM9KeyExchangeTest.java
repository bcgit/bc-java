package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.agreement.SM9KeyExchange;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncUserKeyParametersGenerator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Known-answer test for the SM9 key exchange protocol (GM/T 0044.3-2016) against both GM/T 0044.5-2016
 * Annex B vectors - the Chinese edition's (hid = 0x02, crypto/sm9/sm9_keyexchange.txt) and the English
 * edition's (hid = 0x03, crypto/sm9/sm9_keyexchange_hid03.txt), the hid being the KGC's published choice,
 * taken from the file. The master public key, both user keys, both ephemerals, the shared key and S_A / S_B
 * are reproduced byte-for-byte, with party A on a key rebuilt through fromEncodedExchangeKey, as a party
 * holding its KGC-served key but not the master private key does.
 */
public class SM9KeyExchangeTest
    extends SimpleTest
{
    // never written to: every check that changes an identity array works on its own copy
    private static final byte[] ALICE = { 'A', 'l', 'i', 'c', 'e' };
    private static final byte[] BOB = { 'B', 'o', 'b' };

    public String getName()
    {
        return "SM9KeyExchange";
    }

    public void performTest()
        throws Exception
    {
        checkVector("sm9_keyexchange.txt");
        checkVector("sm9_keyexchange_hid03.txt");
        checkHidValidation();
        checkEphemeralAnswersOnePeerValue();
        checkSecretPowersDraw();
        checkTagsFollowTheExchange();
        checkFailedCalculateKeyLeavesNoTags();
        checkUnusableSource();
        checkPeerPointIsOnG1();
        checkPairingIsBilinear();
        checkHardPartFactor();
        checkKeyContextValidation();
        checkPeerIdentityIsCopied();
        checkDegeneratePeerPoint();
    }

    /**
     * A peer whose Q_peer = [H1(ID || hid, N)]P1 + P_pub-e is the point at infinity, the identity the KGC can
     * derive no user key for, is refused by generateEphemeral with the message the KGC and recipientPoint
     * give; the refused call keeps no r, so calculateKey still asks for an ephemeral.
     */
    private void checkDegeneratePeerPoint()
        throws Exception
    {
        BigInteger h1 = SM9Sm3.h1(Arrays.append(BOB, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE), SM9Curve.N);
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(SM9Curve.N.subtract(h1));
        SM9KeyExchange a = new SM9KeyExchange(master.generateExchangeKey(ALICE), BOB, true);
        try
        {
            a.generateEphemeral(CryptoServicesRegistrar.getSecureRandom());
            fail("SM9KeyExchange formed an ephemeral for a peer whose point is at infinity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 encryption master key must be regenerated for this identity".equals(e.getMessage()));
        }
        java.lang.reflect.Field scalar = SM9KeyExchange.class.getDeclaredField("ephemeralScalar");
        scalar.setAccessible(true);
        isTrue("a refused generateEphemeral keeps no ephemeral scalar", scalar.get(a) == null);
        try
        {
            a.calculateKey(128, SM9Curve.P1);
            fail("SM9KeyExchange calculated a key after a refused generateEphemeral");
        }
        catch (IllegalStateException e)
        {
            isTrue("generateEphemeral must be called first".equals(e.getMessage()));
        }
    }

    /**
     * The exchange keeps its own copy of the peer's identity, which forms Q_peer when the ephemeral is
     * generated and goes into Z and both tags when the key is calculated, and refuses a null or empty one.
     */
    private void checkPeerIdentityIsCopied()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x5678));
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

        // the caller overwrites its array straight after construction, and then after the
        // ephemeral values have been exchanged
        for (int when = 0; when != 2; when++)
        {
            byte[] peerOfA = Arrays.clone(BOB);
            SM9KeyExchange a = new SM9KeyExchange(master.generateExchangeKey(ALICE), peerOfA, true);
            SM9KeyExchange b = new SM9KeyExchange(master.generateExchangeKey(BOB), ALICE, false);
            if (when == 0)
            {
                Arrays.fill(peerOfA, (byte)'X');
            }
            ECPoint ra = a.generateEphemeral(random);
            ECPoint rb = b.generateEphemeral(random);
            if (when == 1)
            {
                Arrays.fill(peerOfA, (byte)'X');
            }
            isTrue("the parties agree whatever the caller does with its array [" + when + "]",
                Arrays.areEqual(a.calculateKey(128, rb), b.calculateKey(128, ra)));
            isTrue("and on both confirmation tags [" + when + "]",
                Arrays.areEqual(a.getResponderConfirmation(), b.getResponderConfirmation())
                    && Arrays.areEqual(a.getInitiatorConfirmation(), b.getInitiatorConfirmation()));
        }

        try
        {
            new SM9KeyExchange(master.generateExchangeKey(ALICE), null, true);
            fail("SM9KeyExchange accepted a null peer identity");
        }
        catch (NullPointerException e)
        {
            isTrue("peerIdentity cannot be null".equals(e.getMessage()));
        }
        try
        {
            new SM9KeyExchange(master.generateExchangeKey(ALICE), new byte[0], true);
            fail("SM9KeyExchange accepted an empty peer identity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("peerIdentity cannot be empty".equals(e.getMessage()));
        }
    }

    /**
     * A key's master public key and identity, which arrive beside its point, are required, and the identity
     * may not be empty; the key keeps its own copy of the identity; and the master scalar decodes only at the
     * 32 bytes getEncoded() writes and in [1, N-1], and can be held to its published master public key.
     */
    private void checkKeyContextValidation()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x1357));
        SM9EncMasterPublicKeyParameters pub = master.getPublicKeyParameters();
        byte[] enc = master.generateUserKey(ALICE, SM9EncMasterPrivateKeyParameters.HID).getEncoded();
        byte hid = SM9EncMasterPrivateKeyParameters.HID;

        try
        {
            SM9EncPrivateKeyParameters.fromEncoded(enc, null, ALICE, hid);
            fail("fromEncoded accepted a null master public key");
        }
        catch (NullPointerException e)
        {
            isTrue("masterPublicKey cannot be null".equals(e.getMessage()));
        }
        try
        {
            SM9EncPrivateKeyParameters.fromEncoded(enc, pub, null, hid);
            fail("fromEncoded accepted a null identity");
        }
        catch (NullPointerException e)
        {
            isTrue("identity cannot be null".equals(e.getMessage()));
        }
        try
        {
            SM9EncPrivateKeyParameters.fromEncoded(enc, pub, new byte[0], hid);
            fail("fromEncoded accepted an empty identity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("identity cannot be empty".equals(e.getMessage()));
        }
        try
        {
            master.generateUserKey(new byte[0], hid);
            fail("the KGC derived a key for the empty identity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("identity cannot be empty".equals(e.getMessage()));
        }
        try
        {
            pub.getUserPublicKey(new byte[0], hid);
            fail("a recipient key was formed for the empty identity");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("identity cannot be empty".equals(e.getMessage()));
        }

        // destroy() zeroes the key's own copy of the identity, not the caller's array
        byte[] callers = "Carol".getBytes("US-ASCII");
        SM9EncPrivateKeyParameters rebuilt = SM9EncPrivateKeyParameters.fromEncoded(
            master.generateUserKey(callers, hid).getEncoded(), pub, callers, hid);
        rebuilt.destroy();
        isTrue("destroying a key leaves the caller's identity array intact",
            Arrays.areEqual(callers, "Carol".getBytes("US-ASCII")));

        // the master scalar reads back only at the width it is written
        isTrue("a 32-byte master scalar still decodes",
            SM9EncMasterPrivateKeyParameters.fromEncoded(master.getEncoded()) != null);
        byte[][] wrongLengths = { new byte[31], new byte[33], new byte[2] };
        for (int i = 0; i != wrongLengths.length; i++)
        {
            wrongLengths[i][wrongLengths[i].length - 1] = 0x07;
            try
            {
                SM9EncMasterPrivateKeyParameters.fromEncoded(wrongLengths[i]);
                fail("a master scalar decoded from " + wrongLengths[i].length + " bytes");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("SM9 master private key must be 32 bytes".equals(e.getMessage()));
            }
        }

        // ... and only in [1, N-1], whether constructed or decoded
        BigInteger[] outOfRange = { BigInteger.ZERO, SM9Curve.N, SM9Curve.N.add(BigInteger.ONE), BigInteger.valueOf(-1) };
        for (int i = 0; i != outOfRange.length; i++)
        {
            try
            {
                new SM9EncMasterPrivateKeyParameters(outOfRange[i]);
                fail("an encryption master scalar of " + outOfRange[i] + " was taken");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("ke must be in [1, N-1]".equals(e.getMessage()));
            }
        }
        try
        {
            SM9EncMasterPrivateKeyParameters.fromEncoded(BigIntegers.asUnsignedByteArray(32, SM9Curve.N));
            fail("an encryption master scalar of N was decoded");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("ke must be in [1, N-1]".equals(e.getMessage()));
        }

        // and can be held to the KGC's published master public key: a scalar decoded alone always agrees
        // with the public key it derives, so only this tells a stale or substituted one from the KGC's
        isTrue("a master scalar rebuilds against its own public key", Arrays.areEqual(master.getEncoded(),
            SM9EncMasterPrivateKeyParameters.fromEncoded(master.getEncoded(), pub).getEncoded()));
        try
        {
            SM9EncMasterPrivateKeyParameters.fromEncoded(
                new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x1358)).getEncoded(), pub);
            fail("a master scalar rebuilt against another key's public key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 master private key does not match its master public key".equals(e.getMessage()));
        }
    }

    /**
     * The peer's ephemeral has to be a point of SM9's G1: ECPoint.isValid() answers only for the curve the
     * point carries with it. The pairing refuses arguments outside G1 and G2 itself.
     */
    private void checkPeerPointIsOnG1()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x2468));

        SM9KeyExchange a = new SM9KeyExchange(master.generateExchangeKey(ALICE), BOB, true);
        a.generateEphemeral(CryptoServicesRegistrar.getSecureRandom());

        ECPoint foreign = CustomNamedCurves.getByName("P-256").getG();
        try
        {
            a.calculateKey(128, foreign);
            fail("SM9KeyExchange accepted a peer point from another curve");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("invalid SM9 peer ephemeral point".equals(e.getMessage()));
        }

        // the pairing refuses both arguments itself, rather than reading affine coordinates that do not
        // exist or pairing a point of an unrelated curve
        ECPoint[] g1s = { foreign, SM9Curve.G1.getInfinity(), SM9Curve.P1 };
        SM9G2Point[] g2s = { SM9Curve.P2, SM9Curve.P2, SM9Curve.P2.multiply(BigInteger.ZERO) };
        String[] what = { "a G1 argument from another curve", "the point at infinity on G1", "the point at infinity on G2" };
        for (int i = 0; i != g1s.length; i++)
        {
            try
            {
                SM9Pairing.pairing(g1s[i], g2s[i]);
                fail("SM9Pairing paired " + what[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(((i < 2) ? "SM9 pairing first argument is not a point of G1"
                    : "SM9 pairing second argument is not a point of G2").equals(e.getMessage()));
            }
        }
        isTrue("e(P1, P2) still computes", SM9Pairing.pairing(SM9Curve.P1, SM9Curve.P2) != null);
    }

    /**
     * The Miller loop starts from a random representative of its G2 argument, so the randomness has to cancel:
     * the pairing gives the same value on every call, and is bilinear for points other than the vectors'.
     */
    private void checkPairingIsBilinear()
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger nMinusOne = SM9Curve.N.subtract(BigInteger.ONE);
        Fp12 g = SM9Pairing.pairing(SM9Curve.P1, SM9Curve.P2);
        for (int i = 0; i != 2; i++)
        {
            BigInteger a = BigIntegers.createRandomInRange(BigInteger.ONE, nMinusOne, random);
            BigInteger b = BigIntegers.createRandomInRange(BigInteger.ONE, nMinusOne, random);
            ECPoint p = SM9Curve.P1.multiply(a).normalize();
            SM9G2Point q = SM9Curve.P2.multiply(b);

            Fp12 e = SM9Pairing.pairing(p, q);
            isTrue("the pairing answers the same on every call", e.equals(SM9Pairing.pairing(p, q)));
            isTrue("e([a]P1, [b]P2) = e(P1, P2)^ab", e.equals(g.pow(a.multiply(b).mod(SM9Curve.N))));
        }
    }

    /**
     * The value the second part of the final exponentiation runs on is given a random factor of its own, rho,
     * from the subgroup that part takes to 1 - so no pairing value can show whether rho is applied at all, or
     * right - and is checked here directly, through reflection. rho is B^(e + 2^11 - 1), for a base B of that
     * subgroup drawn once and an e of 64 bits drawn for each call, taken by a comb of eleven columns of six bits
     * over a table of sixty-four powers of B, each carrying a factor B so that none is 1. With the default source
     * fixed, an element of the subgroup is drawn as B is and rebuilt from the six F_p2 draws z it is made from:
     * it has to be z^((q^6 - 1)(q^2 + 1)N), not 1, and taken to 1 by the second part. The table's base has to be
     * taken to 1 without being 1, and each entry has to be its power of the base, with no coefficient 0; the
     * comb has to give B^(e + 2^11 - 1) for each single bit e, both ends of its range and at random; and rho has
     * to be B^(e + 2^11 - 1) for the e its draw gives, read big-endian, whichever entries the lookups start at -
     * every power taken here by a plain square-and-multiply. The final exponentiation has to draw rho, one draw
     * of 8 bytes, and those entries, one of 11, where the rest of it draws the 32 bytes of an F_q element.
     */
    private void checkHardPartFactor()
        throws Exception
    {
        java.lang.reflect.Method element = pairingMethod("randomKernelElement", new Class[0]);
        java.lang.reflect.Method table = pairingMethod("kernelTable", new Class[0]);
        java.lang.reflect.Method power = pairingMethod("kernelPower", new Class[]{ long.class });
        java.lang.reflect.Method kernel = pairingMethod("hardPartKernel", new Class[0]);
        java.lang.reflect.Method hardPart = pairingMethod("hardPart", new Class[]{ Fp12.class });
        java.lang.reflect.Method finalExponentiation = pairingMethod("finalExponentiation", new Class[]{ Fp12.class });
        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        java.lang.reflect.Method draw = fp2.getDeclaredMethod("randomNonZero", new Class[0]);
        draw.setAccessible(true);
        Class fp4 = Class.forName("org.bouncycastle.math.ec.sm9.Fp4");
        java.lang.reflect.Constructor newFp4 = fp4.getDeclaredConstructor(new Class[]{ fp2, fp2 });
        newFp4.setAccessible(true);
        java.lang.reflect.Constructor newFp12 = Fp12.class.getDeclaredConstructor(new Class[]{ fp4, fp4, fp4 });
        newFp12.setAccessible(true);
        java.lang.reflect.Constructor fromLimbs = Fp12.class.getDeclaredConstructor(new Class[]{ int[].class });
        fromLimbs.setAccessible(true);
        java.lang.reflect.Field oneField = Fp12.class.getDeclaredField("ONE");
        oneField.setAccessible(true);
        Fp12 one = (Fp12)oneField.get(null);

        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        BigInteger e = q.pow(6).subtract(BigInteger.ONE).multiply(q.pow(2).add(BigInteger.ONE)).multiply(SM9Curve.N);

        // the table is made on its first call, from the default source as it is then: here, before it is fixed
        int[] limbs = (int[])table.invoke(null, new Object[0]);

        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        Fp12 previous = null;
        Fp12 z = null;
        try
        {
            for (int i = 0; i != 3; i++)
            {
                // ample for the six draws, each of 32 bytes, repeated until the value is in range
                byte[] source = new byte[2048];
                random.nextBytes(source);

                CryptoServicesRegistrar.setSecureRandom(new FixedSecureRandom(source));
                Fp12 y = (Fp12)element.invoke(null, new Object[0]);

                CryptoServicesRegistrar.setSecureRandom(new FixedSecureRandom(source));
                Object[] c = new Object[3];
                for (int j = 0; j != c.length; j++)
                {
                    Object c0 = draw.invoke(null, new Object[0]);
                    Object c1 = draw.invoke(null, new Object[0]);
                    c[j] = newFp4.newInstance(new Object[]{ c0, c1 });
                }
                z = (Fp12)newFp12.newInstance(c);
                CryptoServicesRegistrar.setSecureRandom(null);

                isTrue("the base's draw is z^((q^6 - 1)(q^2 + 1)N)", y.equals(plainPow(z, e)));
                isTrue("the base's draw is not 1", !y.equals(one));
                isTrue("the second part takes the base's draw to 1", one.equals(hardPart.invoke(null, new Object[]{ y })));
                isTrue("the base's draw is made afresh", previous == null || !y.equals(previous));
                previous = y;
            }

            isTrue("the comb's table is made once", table.invoke(null, new Object[0]) == limbs);
            // sixty-four entries of twelve coefficients, each eight limbs
            isTrue("the comb's table holds sixty-four entries", limbs.length == 64 * 12 * 8);
            Fp12[] entry = new Fp12[64];
            int size = limbs.length / entry.length;
            for (int d = 0; d != entry.length; d++)
            {
                entry[d] = (Fp12)fromLimbs.newInstance(new Object[]{ Arrays.copyOfRange(limbs, d * size, (d + 1) * size) });
            }
            Fp12 base = entry[0];
            isTrue("the comb's base is not 1", !base.equals(one));
            isTrue("the second part takes the comb's base to 1", one.equals(hardPart.invoke(null, new Object[]{ base })));
            for (int d = 0; d != entry.length; d++)
            {
                // entry d = d0 + 2d1 + ... + 32d5 is B^(1 + d0 + d1 2^11 + ... + d5 2^55), with no
                // coefficient 0, as a random element of the subgroup has none
                BigInteger x = BigInteger.ONE;
                for (int i = 0; i != 6; i++)
                {
                    if (((d >>> i) & 1) != 0)
                    {
                        x = x.add(BigInteger.ONE.shiftLeft(11 * i));
                    }
                }
                isTrue("the comb's entry " + d, entry[d].equals(power(base, x, one)));
                for (int j = d * size; j != (d + 1) * size; j += 8)
                {
                    int bits = 0;
                    for (int w = 0; w != 8; w++)
                    {
                        bits |= limbs[j + w];
                    }
                    isTrue("the comb's entry " + d + " has no coefficient 0", bits != 0);
                }
            }

            // the 1 in each of the eleven entries the comb reads adds 2^11 - 1 to the exponent
            BigInteger offset = BigInteger.ONE.shiftLeft(11).subtract(BigInteger.ONE);

            // each single bit, the two ends of the range, and at random
            long[] exponents = new long[64 + 8];
            for (int k = 0; k != 64; k++)
            {
                exponents[k] = 1L << k;
            }
            exponents[64] = 0;
            exponents[65] = -1;
            for (int k = 66; k != exponents.length; k++)
            {
                exponents[k] = random.nextLong();
            }
            for (int k = 0; k != exponents.length; k++)
            {
                BigInteger x = new BigInteger(1, Pack.longToBigEndian(exponents[k]));
                isTrue("the comb gives B^(" + x.toString(16) + " + 2^11 - 1)",
                    power(base, x.add(offset), one).equals(power.invoke(null, new Object[]{ Longs.valueOf(exponents[k]) })));
            }

            for (int i = 0; i != 3; i++)
            {
                // e, then the entries the comb's eleven lookups start at: all 0, all 0xFF, at random
                byte[] source = new byte[8 + 11];
                random.nextBytes(source);
                if (i < 2)
                {
                    Arrays.fill(source, 8, source.length, (byte)(i == 0 ? 0x00 : 0xFF));
                }
                CryptoServicesRegistrar.setSecureRandom(new FixedSecureRandom(source));
                Fp12 rho = (Fp12)kernel.invoke(null, new Object[0]);
                CryptoServicesRegistrar.setSecureRandom(null);

                isTrue("rho is B^(e + 2^11 - 1) for the e drawn, whatever the lookups start at",
                    rho.equals(power(base, new BigInteger(1, Arrays.copyOfRange(source, 0, 8)).add(offset), one)));
                isTrue("the second part takes rho to 1", one.equals(hardPart.invoke(null, new Object[]{ rho })));
            }
            isTrue("rho is drawn afresh", !kernel.invoke(null, new Object[0]).equals(kernel.invoke(null, new Object[0])));

            CountingRandom counting = new CountingRandom(random);
            CryptoServicesRegistrar.setSecureRandom(counting);
            finalExponentiation.invoke(null, new Object[]{ z });
            isTrue("the final exponentiation draws rho and the entries its comb's lookups start at",
                counting.eights == 1 && counting.elevens == 1);
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
    }

    // x^e by plainPow, and 1 for e = 0
    private static Fp12 power(Fp12 x, BigInteger e, Fp12 one)
    {
        return e.signum() == 0 ? one : plainPow(x, e);
    }

    /**
     * Counts the draws of 8 bytes, and of 11, made from it, each a call to nextBytes.
     */
    private static class CountingRandom
        extends SecureRandom
    {
        private final SecureRandom delegate;

        int eights, elevens;

        CountingRandom(SecureRandom delegate)
        {
            this.delegate = delegate;
        }

        public void nextBytes(byte[] bytes)
        {
            if (bytes.length == 8)
            {
                eights++;
            }
            if (bytes.length == 11)
            {
                elevens++;
            }
            delegate.nextBytes(bytes);
        }
    }

    private static java.lang.reflect.Method pairingMethod(String name, Class[] parameterTypes)
        throws Exception
    {
        java.lang.reflect.Method m = SM9Pairing.class.getDeclaredMethod(name, parameterTypes);
        m.setAccessible(true);
        return m;
    }

    // x^e for a positive e, by a left-to-right square-and-multiply over the general product, which holds in all of F_p12
    private static Fp12 plainPow(Fp12 x, BigInteger e)
    {
        Fp12 r = x;
        for (int i = e.bitLength() - 2; i >= 0; --i)
        {
            r = r.multiply(r);
            if (e.testBit(i))
            {
                r = r.multiply(x);
            }
        }
        return r;
    }

    /**
     * calculateKey raises to the secret r twice for either party - e(P_pub-e, P2) through powSecureFixedBase
     * and the pairing with the peer's point through powSecure - and ConstantTimeUsageTest's scan of the class
     * is satisfied by either call, so either could turn variable-time unseen. Both draw a fixed number of times,
     * so each party's calculateKey is held to exactly the draws of one pairing, one powSecure and one
     * powSecureFixedBase, from a source whose draws are all usable, once the keys have made what they keep.
     */
    private void checkSecretPowersDraw()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x4321));
        SM9EncPrivateKeyParameters keyA = master.generateExchangeKey(ALICE);
        SM9EncPrivateKeyParameters keyB = master.generateExchangeKey(BOB);
        BigInteger k = new BigInteger("3C5E8A1F9D2B4C6E8F0A1B3D5E7F9A2C4E6B8D0F1A3C5E7B9D2F4A6C8E0B2D4", 16);
        UsableDraws source = new UsableDraws(CryptoServicesRegistrar.getSecureRandom());
        try
        {
            CryptoServicesRegistrar.setSecureRandom(source);
            for (int round = 0; round != 3; round++)
            {
                SM9KeyExchange a = new SM9KeyExchange(keyA, BOB, true);
                SM9KeyExchange b = new SM9KeyExchange(keyB, ALICE, false);
                ECPoint ra = a.generateEphemeral(source);
                ECPoint rb = b.generateEphemeral(source);
                source.calls = 0;
                byte[] skA = a.calculateKey(128, rb);
                int drawsA = source.calls;
                source.calls = 0;
                byte[] skB = b.calculateKey(128, ra);
                int drawsB = source.calls;
                isTrue("SM9 key exchange agrees", Arrays.areEqual(skA, skB));
                if (round == 0)
                {
                    // the first exchange makes what the keys keep
                    continue;
                }
                for (int role = 0; role != 2; role++)
                {
                    SM9EncPrivateKeyParameters key = (role == 0) ? keyA : keyB;
                    source.calls = 0;
                    key.getMasterPublicKey().pairingWithP2().powSecureFixedBase(k);
                    int fixedBase = source.calls;
                    source.calls = 0;
                    Fp12 g = SM9Pairing.pairing((role == 0) ? rb : ra, key.getPrivatePoint());
                    int pairing = source.calls;
                    source.calls = 0;
                    g.powSecure(k);
                    int secure = source.calls;
                    isTrue("powSecureFixedBase, the pairing and powSecure each draw: " + fixedBase + ", "
                        + pairing + ", " + secure, fixedBase > 0 && pairing > 0 && secure > 0);
                    int draws = (role == 0) ? drawsA : drawsB;
                    isTrue(((role == 0) ? "the initiator's" : "the responder's") + " calculateKey draws "
                        + draws + " times, where one pairing, one powSecure and one powSecureFixedBase draw "
                        + (fixedBase + pairing + secure), draws == fixedBase + pairing + secure);
                }
            }
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
    }

    /**
     * A source whose draws are all usable, so that an operation draws from it a fixed number of times: each
     * 32-byte draw has its first and last byte cleared, which puts it below q and N whichever way round it is
     * read. The calls to nextBytes are counted.
     */
    private static class UsableDraws
        extends SecureRandom
    {
        private final SecureRandom delegate;

        int calls;

        UsableDraws(SecureRandom delegate)
        {
            this.delegate = delegate;
        }

        public void nextBytes(byte[] bytes)
        {
            calls++;
            delegate.nextBytes(bytes);
            if (bytes.length == 32)
            {
                bytes[0] = 0;
                bytes[31] = 0;
            }
        }
    }

    /**
     * GM/T 0044.3-2016 6.1 A2 and B2 draw a fresh r for each exchange, so the ephemeral is discarded once it
     * has derived a key: it answers one peer value only, while the tags of its exchange stay available.
     */
    private void checkEphemeralAnswersOnePeerValue()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x4321));
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

        SM9KeyExchange a = new SM9KeyExchange(master.generateExchangeKey(ALICE), BOB, true);
        SM9KeyExchange b = new SM9KeyExchange(master.generateExchangeKey(BOB), ALICE, false);
        SM9KeyExchange b2 = new SM9KeyExchange(master.generateExchangeKey(BOB), ALICE, false);

        ECPoint ra = a.generateEphemeral(random);
        ECPoint rb = b.generateEphemeral(random);
        ECPoint rb2 = b2.generateEphemeral(random);

        byte[] skA = a.calculateKey(128, rb);
        byte[] skB = b.calculateKey(128, ra);
        isTrue("SM9 key exchange agrees", Arrays.areEqual(skA, skB));
        isTrue("S_B survives the ephemeral being discarded",
            Arrays.areEqual(a.getResponderConfirmation(), b.getResponderConfirmation()));
        isTrue("S_A survives the ephemeral being discarded",
            Arrays.areEqual(a.getInitiatorConfirmation(), b.getInitiatorConfirmation()));

        try
        {
            a.calculateKey(128, rb2);
            fail("SM9KeyExchange answered a second peer ephemeral with the same r");
        }
        catch (IllegalStateException e)
        {
            isTrue("generateEphemeral must be called first".equals(e.getMessage()));
        }

        // a fresh ephemeral starts a further exchange as before
        ECPoint ra2 = a.generateEphemeral(random);
        byte[] skA2 = a.calculateKey(128, rb2);
        byte[] skB2 = b2.calculateKey(128, ra2);
        isTrue("SM9 key exchange agrees on a fresh ephemeral", Arrays.areEqual(skA2, skB2));
        isTrue("a fresh ephemeral gives a different key", !Arrays.areEqual(skA, skA2));
    }

    /**
     * The confirmation tags belong to the exchange that computed them: none are handed out once a further
     * generateEphemeral begins another exchange, nor after a calculateKey the exchange refuses.
     */
    private void checkTagsFollowTheExchange()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x4321));
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

        SM9KeyExchange a = new SM9KeyExchange(master.generateExchangeKey(ALICE), BOB, true);
        SM9KeyExchange b = new SM9KeyExchange(master.generateExchangeKey(BOB), ALICE, false);

        ECPoint ra = a.generateEphemeral(random);
        ECPoint rb = b.generateEphemeral(random);
        a.calculateKey(128, rb);
        b.calculateKey(128, ra);
        byte[] firstSB = a.getResponderConfirmation();

        ECPoint ra2 = a.generateEphemeral(random);
        checkNoTags(a, "once a further exchange has begun");

        // a calculateKey the exchange refuses completes nothing
        try
        {
            a.calculateKey(128, SM9Curve.G1.getInfinity());
            fail("SM9KeyExchange took the point at infinity as the peer ephemeral");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("invalid SM9 peer ephemeral point".equals(e.getMessage()));
        }
        checkNoTags(a, "after a refused calculateKey");

        // the exchange then completes, with tags of its own
        ECPoint rb2 = b.generateEphemeral(random);
        a.calculateKey(128, rb2);
        b.calculateKey(128, ra2);
        isTrue("S_B of the second exchange agrees",
            Arrays.areEqual(a.getResponderConfirmation(), b.getResponderConfirmation()));
        isTrue("S_A of the second exchange agrees",
            Arrays.areEqual(a.getInitiatorConfirmation(), b.getInitiatorConfirmation()));
        isTrue("the second exchange has an S_B of its own",
            !Arrays.areEqual(firstSB, a.getResponderConfirmation()));
    }

    /**
     * A calculateKey that fails part way - here the default source failing at each of the draws the pairing
     * and the two exponentiations make, for either party - leaves no tags, as for an exchange that has not
     * completed, and keeps the ephemeral, so the exchange then completes, tags and all.
     */
    private void checkFailedCalculateKeyLeavesNoTags()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x4321));
        SM9EncPrivateKeyParameters keyA = master.generateExchangeKey(ALICE);
        SM9EncPrivateKeyParameters keyB = master.generateExchangeKey(BOB);
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

        for (int role = 0; role != 2; role++)
        {
            // calculateKey draws at least 14 times, so each of these fails within it
            for (int draw = 0; draw != 14; draw++)
            {
                SM9KeyExchange a = new SM9KeyExchange(keyA, BOB, true);
                SM9KeyExchange b = new SM9KeyExchange(keyB, ALICE, false);
                ECPoint ra = a.generateEphemeral(random);
                ECPoint rb = b.generateEphemeral(random);
                SM9KeyExchange failing = (role == 0) ? a : b;
                String when = "after " + ((role == 0) ? "the initiator's" : "the responder's")
                    + " calculateKey failed at draw " + draw;
                try
                {
                    CryptoServicesRegistrar.setSecureRandom(new FailingSource(random, draw));
                    failing.calculateKey(128, (role == 0) ? rb : ra);
                    fail("calculateKey completed with a source that fails at draw " + draw);
                }
                catch (IllegalStateException e)
                {
                    isTrue("the source's failure " + when + ": " + e.getMessage(), "source failed".equals(e.getMessage()));
                }
                finally
                {
                    CryptoServicesRegistrar.setSecureRandom(null);
                }
                checkNoTags(failing, when);

                byte[] skA = a.calculateKey(128, rb);
                byte[] skB = b.calculateKey(128, ra);
                isTrue("SM9 key exchange agrees " + when, Arrays.areEqual(skA, skB));
                isTrue("S_B agrees " + when, Arrays.areEqual(a.getResponderConfirmation(), b.getResponderConfirmation()));
                isTrue("S_A agrees " + when, Arrays.areEqual(a.getInitiatorConfirmation(), b.getInitiatorConfirmation()));
            }
        }
    }

    /**
     * A source that fails at a given draw, a call to nextBytes, and draws from another before it.
     */
    private static class FailingSource
        extends SecureRandom
    {
        private final SecureRandom delegate;
        private final int failAt;

        private int calls;

        FailingSource(SecureRandom delegate, int failAt)
        {
            this.delegate = delegate;
            this.failAt = failAt;
        }

        public void nextBytes(byte[] bytes)
        {
            if (calls++ == failAt)
            {
                throw new IllegalStateException("source failed");
            }
            delegate.nextBytes(bytes);
        }
    }

    /**
     * A source that yields nothing usable - only zeros, or only ones - is refused once the draws allowed are
     * used up, rather than hanging or having a fallback stand in for r. These run out after 256 draws, so a
     * draw without a bound fails the test rather than hanging it.
     */
    private void checkUnusableSource()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x4321));
        for (int fill = 0x00; fill <= 0xFF; fill += 0xFF)
        {
            byte[] source = new byte[32 * 256];
            Arrays.fill(source, (byte)fill);
            SM9KeyExchange a = new SM9KeyExchange(master.generateExchangeKey(ALICE), BOB, true);
            try
            {
                a.generateEphemeral(new FixedSecureRandom(source));
                fail("SM9KeyExchange drew an ephemeral from a source that yields only 0x" + Integer.toHexString(fill));
            }
            catch (IllegalStateException e)
            {
                isTrue("SM9 key exchange could not draw a usable ephemeral".equals(e.getMessage()));
            }
        }
    }

    private void checkNoTags(SM9KeyExchange exchange, String when)
    {
        try
        {
            exchange.getResponderConfirmation();
            fail("SM9KeyExchange handed out S_B " + when);
        }
        catch (IllegalStateException e)
        {
            isTrue("calculateKey must be called first".equals(e.getMessage()));
        }
        try
        {
            exchange.getInitiatorConfirmation();
            fail("SM9KeyExchange handed out S_A " + when);
        }
        catch (IllegalStateException e)
        {
            isTrue("calculateKey must be called first".equals(e.getMessage()));
        }
    }

    private void checkVector(String fileName)
        throws Exception
    {
        Map v = SM9Vectors.load(fileName);
        BigInteger ke = new BigInteger((String)v.get("ke"), 16);
        byte[] identityA = SM9Vectors.hex(v, "IDA");
        byte[] identityB = SM9Vectors.hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));
        byte hid = (byte)Integer.parseInt((String)v.get("hid"), 16);

        // named exchange keys under the hid the vector's KGC published
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(ke);
        SM9EncPrivateKeyParameters deA = master.generateExchangeKey(identityA, hid);
        SM9EncPrivateKeyParameters deB = master.generateExchangeKey(identityB, hid);
        isTrue(fileName + " deA records its hid", deA.getHid() == hid);
        isTrue(fileName + " deA is an exchange key", deA.isExchangeKey());

        // the master public key and both KGC-derived user keys the standard prints
        isTrue(fileName + " master public key Ppub-e", Arrays.areEqual(
            master.getPublicKeyParameters().getEncoded(),
            Arrays.concatenate(new byte[]{0x04}, SM9Vectors.hex(v, "Ppube_x"), SM9Vectors.hex(v, "Ppube_y"))));
        isTrue(fileName + " user key deA", Arrays.areEqual(
            deA.getPrivatePoint().getEncoded(), SM9Vectors.g2(v, "deA_x_hi", "deA_x_lo", "deA_y_hi", "deA_y_lo")));
        isTrue(fileName + " user key deB", Arrays.areEqual(
            deB.getPrivatePoint().getEncoded(), SM9Vectors.g2(v, "deB_x_hi", "deB_x_lo", "deB_y_hi", "deB_y_lo")));

        // party A runs on a key rebuilt from its point encoding, as a party served by the KGC imports it,
        // and must reproduce the exchange byte-for-byte
        SM9EncPrivateKeyParameters deAImported = SM9EncPrivateKeyParameters.fromEncodedExchangeKey(
            deA.getEncoded(), master.getPublicKeyParameters(), identityA, hid);
        isTrue(fileName + " imported deA is an exchange key", deAImported.isExchangeKey());
        isTrue(fileName + " imported deA records its hid", deAImported.getHid() == hid);

        SM9KeyExchange a = new SM9KeyExchange(deAImported, identityB, true);
        SM9KeyExchange b = new SM9KeyExchange(deB, identityA, false);
        ECPoint ra = a.generateEphemeral(new TestRandomBigInteger(256, SM9Vectors.hex(v, "rA")));
        ECPoint rb = b.generateEphemeral(new TestRandomBigInteger(256, SM9Vectors.hex(v, "rB")));

        isTrue(fileName + " RA", Arrays.areEqual(SM9Curve.g1ToBytes(ra),
            Arrays.concatenate(SM9Vectors.hex(v, "RA_x"), SM9Vectors.hex(v, "RA_y"))));
        isTrue(fileName + " RB", Arrays.areEqual(SM9Curve.g1ToBytes(rb),
            Arrays.concatenate(SM9Vectors.hex(v, "RB_x"), SM9Vectors.hex(v, "RB_y"))));

        byte[] skA = a.calculateKey(klen, rb);
        byte[] skB = b.calculateKey(klen, ra);
        isTrue(fileName + " SKA", Arrays.areEqual(skA, SM9Vectors.hex(v, "SK")));
        isTrue(fileName + " SKB", Arrays.areEqual(skB, SM9Vectors.hex(v, "SK")));

        isTrue(fileName + " S_B", Arrays.areEqual(b.getResponderConfirmation(), SM9Vectors.hex(v, "S_B")));
        isTrue(fileName + " S_B (initiator agrees)", Arrays.areEqual(a.getResponderConfirmation(), SM9Vectors.hex(v, "S_B")));
        isTrue(fileName + " S_A", Arrays.areEqual(a.getInitiatorConfirmation(), SM9Vectors.hex(v, "S_A")));
        isTrue(fileName + " S_A (responder agrees)", Arrays.areEqual(b.getInitiatorConfirmation(), SM9Vectors.hex(v, "S_A")));

        // a non-positive key length, for which the KDF gives no output, is refused
        try
        {
            a.calculateKey(0, rb);
            fail("SM9KeyExchange accepted klenBits = 0");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("klenBits must be positive".equals(e.getMessage()));
        }
        try
        {
            a.calculateKey(-8, rb);
            fail("SM9KeyExchange accepted klenBits = -8");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("negative klenBits message: " + e.getMessage(), "klenBits must be positive".equals(e.getMessage()));
        }
        // and so is one that is not a whole number of bytes, before the ephemeral is spent
        SM9KeyExchange fresh = new SM9KeyExchange(deB, identityA, false);
        ECPoint rFresh = fresh.generateEphemeral(CryptoServicesRegistrar.getSecureRandom());
        try
        {
            fresh.calculateKey(12, ra);
            fail("SM9KeyExchange accepted klenBits = 12");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("fractional klenBits refused by the exchange itself: " + e.getMessage(),
                "klenBits must be a whole number of bytes".equals(e.getMessage()));
        }
        isTrue("the ephemeral survives a refused key length",
            fresh.calculateKey(klen, ra).length == klen / 8 && rFresh != null);
    }

    private void checkHidValidation()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x1234));
        // GM/T 0044.3-2016 6.1 leaves the hid to the KGC, constraining it only to one byte, so a hid other than
        // the worked examples' is served rather than refused, as the explicit-hid entry points document
        byte[] otherHids = new byte[]{ (byte)0x00, (byte)0x01, (byte)0x04, (byte)0xFF };
        for (int i = 0; i != otherHids.length; i++)
        {
            SM9EncPrivateKeyParameters kem = master.generateUserKey(ALICE, otherHids[i]);
            isTrue("a KEM key under a KGC-chosen hid records it", kem.getHid() == otherHids[i]);
            isTrue("and imports under it", Arrays.areEqual(SM9EncPrivateKeyParameters.fromEncoded(
                kem.getEncoded(), master.getPublicKeyParameters(), ALICE, otherHids[i]).getEncoded(), kem.getEncoded()));

            SM9EncPrivateKeyParameters exch = master.generateExchangeKey(ALICE, otherHids[i]);
            isTrue("an exchange key under a KGC-chosen hid records it", exch.getHid() == otherHids[i]);
            isTrue("and is an exchange key", exch.isExchangeKey());
            isTrue("and imports under it", SM9EncPrivateKeyParameters.fromEncodedExchangeKey(
                exch.getEncoded(), master.getPublicKeyParameters(), ALICE, otherHids[i]).getHid() == otherHids[i]);

            // the two functions stay distinct exactly when the KGC's two published values are: here this hid
            // and another, differing from it in bit 6
            isTrue("a KGC's two hids give two different points",
                !Arrays.areEqual(kem.getEncoded(), master.generateUserKey(ALICE, (byte)(otherHids[i] ^ 0x40)).getEncoded()));
        }
        // the published identifier values pass: the exchange's here, and the KEM side's, through the
        // interface, where kemKey is derived below
        SM9EncUserKeyParametersGenerator kgc = master;
        isTrue(master.generateExchangeKey(ALICE).getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);

        // ... but a KEM / decryption key is not derived under the exchange's own hid, which names the exchange
        try
        {
            kgc.generateUserKey(ALICE, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
            fail("generateUserKey accepted HID_EXCHANGE");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(("hid must not be HID_EXCHANGE (0x02) for a KEM or decryption user key - that hid "
                + "names the key exchange").equals(e.getMessage()));
        }

        // the import checks the claimed usage against the hid the same way
        try
        {
            SM9EncPrivateKeyParameters.fromEncoded(master.generateExchangeKey(ALICE).getEncoded(), master.getPublicKeyParameters(),
                ALICE, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
            fail("fromEncoded accepted HID_EXCHANGE");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(("hid must not be HID_EXCHANGE (0x02) for a KEM or decryption user key - that hid "
                + "names the key exchange").equals(e.getMessage()));
        }
        // ... while a genuine KEM / decryption key still rebuilds from its encoding
        SM9EncPrivateKeyParameters kemKey = kgc.generateUserKey(ALICE, SM9EncMasterPrivateKeyParameters.HID);
        isTrue("a KEM user key round-trips through its encoding", Arrays.areEqual(
            SM9EncPrivateKeyParameters.fromEncoded(kemKey.getEncoded(), master.getPublicKeyParameters(),
                ALICE, SM9EncMasterPrivateKeyParameters.HID).getEncoded(), kemKey.getEncoded()));

        // the import holds the point, master public key, identity and hid it is given to the KGC's relation
        // e([H1(ID || hid, N)]P1 + P_pub-e, de) = e(P_pub-e, P2)
        byte[] other = "Carol".getBytes("US-ASCII");
        checkImportRefused("a key under the wrong identity", kemKey.getEncoded(),
            master.getPublicKeyParameters(), other, SM9EncMasterPrivateKeyParameters.HID, false);
        SM9EncMasterPrivateKeyParameters otherMaster = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x9ABC));
        checkImportRefused("a key under the wrong master key", kemKey.getEncoded(),
            otherMaster.getPublicKeyParameters(), ALICE, SM9EncMasterPrivateKeyParameters.HID, false);
        checkImportRefused("a key under the wrong hid", kemKey.getEncoded(),
            master.getPublicKeyParameters(), ALICE, (byte)0x04, false);
        // the same holds for an exchange key: the same point under the exchange hid, given and by default
        checkImportRefused("an exchange key under the wrong hid", kemKey.getEncoded(),
            master.getPublicKeyParameters(), ALICE, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE, true);
        try
        {
            SM9EncPrivateKeyParameters.fromEncodedExchangeKey(kemKey.getEncoded(), master.getPublicKeyParameters(), ALICE);
            fail("an exchange key under the default hid was imported for a point derived under another");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage(), MISMATCH.equals(e.getMessage()));
        }
        checkImportRefused("an exchange key under the wrong identity", master.generateExchangeKey(ALICE).getEncoded(),
            master.getPublicKeyParameters(), other, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE, true);
        // and under a master key for which this identity is the one no key can be derived for (ke =
        // -H1(ID || hid, N), so Q is the point at infinity): the check refuses the point
        BigInteger h1 = SM9Sm3.h1(Arrays.append(ALICE, SM9EncMasterPrivateKeyParameters.HID), SM9Curve.N);
        SM9EncMasterPrivateKeyParameters degenerate = new SM9EncMasterPrivateKeyParameters(SM9Curve.N.subtract(h1));
        checkImportRefused("a key under a master key that can derive none for its identity", kemKey.getEncoded(),
            degenerate.getPublicKeyParameters(), ALICE, SM9EncMasterPrivateKeyParameters.HID, false);

        // the check is on the four together, not on the point: under ke' with
        // ke' / (H1(Carol || hid, N) + ke') = ke / (H1(Alice || hid, N) + ke) mod N, Alice's point is
        // Carol's key, and it imports as hers there
        BigInteger ke = new BigInteger(1, master.getEncoded());
        BigInteger hAlice = SM9Sm3.h1(Arrays.append(ALICE, SM9EncMasterPrivateKeyParameters.HID), SM9Curve.N);
        BigInteger hCarol = SM9Sm3.h1(Arrays.append(other, SM9EncMasterPrivateKeyParameters.HID), SM9Curve.N);
        BigInteger c = ke.multiply(hAlice.add(ke).modInverse(SM9Curve.N)).mod(SM9Curve.N);
        SM9EncMasterPrivateKeyParameters carolsMaster = new SM9EncMasterPrivateKeyParameters(
            c.multiply(hCarol).multiply(BigInteger.ONE.subtract(c).modInverse(SM9Curve.N)).mod(SM9Curve.N));
        isTrue("Alice's point is Carol's key under another master key", Arrays.areEqual(
            carolsMaster.generateUserKey(other, SM9EncMasterPrivateKeyParameters.HID).getEncoded(), kemKey.getEncoded()));
        isTrue("and imports as hers there", Arrays.areEqual(SM9EncPrivateKeyParameters.fromEncoded(
            kemKey.getEncoded(), carolsMaster.getPublicKeyParameters(), other,
            SM9EncMasterPrivateKeyParameters.HID).getEncoded(), kemKey.getEncoded()));

        // KEM / decryption keys and exchange keys are refused by each other's consumers
        SM9EncPrivateKeyParameters encKey = master.generateUserKey(ALICE, SM9EncMasterPrivateKeyParameters.HID);
        try
        {
            new SM9KeyExchange(encKey, "Bob".getBytes("US-ASCII"), true);
            fail("SM9KeyExchange accepted a KEM/decryption user key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 key exchange requires a key-exchange user key from generateExchangeKey".equals(e.getMessage()));
        }

        // an exchange key rebuilt from its encoding carries the exchange usage and, by default, the published
        // exchange hid, and the KEM side refuses it as it does a KGC-derived one
        SM9EncPrivateKeyParameters exchKey = master.generateExchangeKey(ALICE);
        SM9EncPrivateKeyParameters imported = SM9EncPrivateKeyParameters.fromEncodedExchangeKey(
            exchKey.getEncoded(), master.getPublicKeyParameters(), ALICE);
        isTrue("imported exchange key claims the exchange usage", imported.isExchangeKey());
        isTrue("imported exchange key defaults to HID_EXCHANGE",
            imported.getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
        try
        {
            new SM9KEMExtractor(imported, 128);
            fail("SM9KEMExtractor accepted an imported key-exchange user key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 KEM decapsulation requires an encryption user key, not a key-exchange key".equals(e.getMessage()));
        }
    }

    private static final String MISMATCH =
        "SM9 encryption private key does not match its master public key, identity and hid";

    private void checkImportRefused(String label, byte[] enc, SM9EncMasterPublicKeyParameters pub, byte[] identity,
                                    byte hid, boolean exchangeKey)
    {
        try
        {
            if (exchangeKey)
            {
                SM9EncPrivateKeyParameters.fromEncodedExchangeKey(enc, pub, identity, hid);
            }
            else
            {
                SM9EncPrivateKeyParameters.fromEncoded(enc, pub, identity, hid);
            }
            fail(label + " was imported");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(label + ": " + e.getMessage(), MISMATCH.equals(e.getMessage()));
        }
    }

    public static void main(String[] args)
    {
        runTest(new SM9KeyExchangeTest());
    }
}
