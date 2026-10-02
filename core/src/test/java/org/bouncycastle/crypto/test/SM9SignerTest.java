package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.SM9SigMasterKeyPairGenerator;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigUserKeyParametersGenerator;
import org.bouncycastle.crypto.signers.SM9Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.math.ec.endo.EndoUtil;
import org.bouncycastle.math.ec.endo.GLVEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * SM9 digital signatures (GM/T 0044.2-2016): the GM/T 0044.5-2016 Annex A vector
 * (crypto/sm9/sm9_signature.txt) reproduced byte-for-byte, the signer's handling of its
 * parameters and input, and the curve, pairing and field arithmetic beneath it.
 */
public class SM9SignerTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9Signer";
    }

    public void performTest()
        throws Exception
    {
        Map v = SM9Vectors.load("sm9_signature.txt");
        BigInteger ks = new BigInteger((String)v.get("ks"), 16);
        byte[] identity = SM9Vectors.hex(v, "IDA");
        byte[] msg = SM9Vectors.hex(v, "M");

        SM9SigMasterPrivateKeyParameters master = new SM9SigMasterPrivateKeyParameters(ks);
        // derive through the KGC extraction interface (hid = 0x01 applied internally)
        SM9SigUserKeyParametersGenerator kgc = master;
        SM9SigPrivateKeyParameters userKey = kgc.generateUserKey(identity);
        SM9SigMasterPublicKeyParameters mpk = master.getPublicKeyParameters();

        // the domain parameters, keys and pairing values GM/T 0044.5-2016 Annex A prints
        checkDomainParameters(v);
        checkKeyDerivation(v, master, userKey);
        checkPairingValues(v, master);

        byte[] sig = sign(new ParametersWithRandom(userKey, new TestRandomBigInteger(256, SM9Vectors.hex(v, "r"))), msg);

        // sig = h(32) || 0x04 || Sx(32) || Sy(32)
        isTrue("SM9 signature h", Arrays.areEqual(Arrays.copyOfRange(sig, 0, 32), SM9Vectors.hex(v, "h")));
        isTrue("SM9 signature S uncompressed prefix", sig[32] == (byte)0x04);
        isTrue("SM9 signature Sx", Arrays.areEqual(Arrays.copyOfRange(sig, 33, 65), SM9Vectors.hex(v, "Sx")));
        isTrue("SM9 signature Sy", Arrays.areEqual(Arrays.copyOfRange(sig, 65, 97), SM9Vectors.hex(v, "Sy")));
        isTrue("SM9 signature verify", verify(mpk, identity, msg, sig));

        // S is taken only in the uncompressed form: the hybrid form (0x06 / 0x07 || x || y) would give
        // the signature a second encoding
        byte[] hybrid = Arrays.clone(sig);
        hybrid[32] = (byte)(((sig[96] & 1) == 0) ? 0x06 : 0x07);
        isTrue("SM9 signature rejects S in hybrid form", !verify(mpk, identity, msg, hybrid));

        // ... and only at exactly 97 bytes: one too short to have a byte 32 answers false as well
        byte[][] wrongLength = { Arrays.append(sig, (byte)0x00), Arrays.copyOfRange(sig, 0, sig.length - 1),
            Arrays.copyOfRange(sig, 0, 10), new byte[0] };
        for (int i = 0; i != wrongLength.length; i++)
        {
            isTrue("SM9 signature of " + wrongLength[i].length + " bytes does not verify",
                !verify(mpk, identity, msg, wrongLength[i]));
        }

        byte[] bad = Arrays.clone(msg);
        bad[0] ^= 0x01;
        isTrue("SM9 signature rejects tampered message", !verify(mpk, identity, bad, sig));

        // a zero-length message signs and verifies; a fixed source, so that a failure here reproduces
        SM9Signer emptySigner = new SM9Signer();
        emptySigner.init(true, new ParametersWithRandom(userKey, new TestRandomBigInteger(256, SM9Vectors.hex(v, "r"))));
        byte[] emptySig = emptySigner.generateSignature();

        SM9Signer emptyVerifier = new SM9Signer();
        emptyVerifier.init(false, new ParametersWithID(mpk, identity));
        isTrue("SM9 zero-length message verifies", emptyVerifier.verifySignature(emptySig));

        SM9Signer emptyWrong = new SM9Signer();
        emptyWrong.init(false, new ParametersWithID(mpk, identity));
        emptyWrong.update((byte)0x00);
        isTrue("SM9 zero-length signature does not verify a non-empty message",
            !emptyWrong.verifySignature(emptySig));

        // a key is refused in the one-octet encoding of the point at infinity, which ds_A = [t2]P1
        // with t2 in [1, N-1] never is, and in the hybrid form, a second encoding of the same point
        byte[][] badKeys = { new byte[]{ 0x00 }, toHybrid(userKey.getEncoded()) };
        String[] refusals = { "SM9 signature private key cannot be the point at infinity",
            "invalid SM9 G1 point encoding" };
        for (int i = 0; i != badKeys.length; i++)
        {
            try
            {
                SM9SigPrivateKeyParameters.fromEncoded(badKeys[i], mpk, identity);
                fail("SM9 signature private key decoded from " + badKeys[i].length + "-byte encoding " + i);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(refusals[i].equals(e.getMessage()));
            }
        }
        // ... and the same on the other G1 key-decode path, the encryption master public key
        byte[] encMpub = new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x77))
            .getPublicKeyParameters().getEncoded();
        isTrue("the uncompressed encryption master public key still decodes",
            SM9EncMasterPublicKeyParameters.fromEncoded(encMpub) != null);
        try
        {
            SM9EncMasterPublicKeyParameters.fromEncoded(toHybrid(encMpub));
            fail("SM9 encryption master public key decoded in hybrid form");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("invalid SM9 G1 point encoding".equals(e.getMessage()));
        }

        // a coordinate at or above q is refused in the decoders' own words, as the forms are
        byte[] q = BigIntegers.asUnsignedByteArray(32, SM9Curve.G1.getField().getCharacteristic());
        for (int i = 0; i != 2; i++)
        {
            byte[] outOfRange = Arrays.clone(encMpub);
            System.arraycopy(q, 0, outOfRange, 1 + 32 * i, 32);
            try
            {
                SM9EncMasterPublicKeyParameters.fromEncoded(outOfRange);
                fail("SM9 G1 point decoded with coordinate " + i + " equal to q");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("g1FromUncompressed refusal of coordinate " + i + ": " + e.getMessage(),
                    "invalid SM9 G1 point encoding".equals(e.getMessage()));
            }
            try
            {
                SM9Curve.g1FromBytes(outOfRange, 1);
                fail("SM9 G1 point decoded from x || y with coordinate " + i + " equal to q");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("g1FromBytes refusal of coordinate " + i + ": " + e.getMessage(),
                    "invalid SM9 G1 point encoding".equals(e.getMessage()));
            }
        }

        checkIdentityCopied(master, identity, msg, sig);
        checkMisuse(master, userKey, identity, sig);
        checkWrapperNesting(master, userKey, identity, msg);
        checkRefusedInit(master, userKey, identity, msg, sig);
        checkUnusableSource(userKey, msg);
        checkUnusableMasterSource();
        checkMessageHashedAsGiven(v, master, userKey, identity, msg, sig);
        checkMasterScalar();
        checkOutOfFieldS(master, identity, msg, sig);
        checkG2Subgroup(master);
        checkG2Multiply();
        checkG2FixedBaseMultiply();
        checkVerificationProduct(master, identity, msg);
        checkMillerLines();
        checkEmptyIdentity(master);
        checkMathEntryPointRanges();
        checkG1UncompressedOnly();
        checkRandomFieldElements();
        checkG1FieldArithmetic();
        checkTowerArithmetic();
        checkCurveArithmetic();
        checkG1SecretMultiply();
        checkG1FixedBaseMultiply();
        checkG1SumOfTwoMultiplies();
        checkG1ResultIsChecked();
        checkG1PublicMultiply();
        checkFixedBaseExponentiation();
        checkSecretExponentiation();
        checkExponentiationByT();
        checkUnusableBlindingSource();

        // the encoding a genuine key round-trips through is still taken
        SM9SigPrivateKeyParameters rebuilt = SM9SigPrivateKeyParameters.fromEncoded(userKey.getEncoded(), mpk, identity);
        byte[] rebuiltSig = sign(new ParametersWithRandom(rebuilt, CryptoServicesRegistrar.getSecureRandom()), msg);
        isTrue("SM9 signature private key round-trips through its encoding", verify(mpk, identity, msg, rebuiltSig));

        checkImportAgainstContext(master, userKey, identity);
        checkDestroyedKeyAtSign(master, identity, msg);
    }

    /**
     * A user key's point is checked on import against the master public key and identity it is filed
     * under, by the KGC's relation e(ds, [H1(ID || hid, N)]P2 + P_pub-s) = e(P1, P_pub-s): one filed
     * under another master public key or another identity is refused, where it imported and made
     * signatures that did not verify.
     */
    private void checkImportAgainstContext(SM9SigMasterPrivateKeyParameters master, SM9SigPrivateKeyParameters userKey,
                                           byte[] identity)
    {
        byte[] enc = userKey.getEncoded();
        SM9SigMasterPublicKeyParameters other = new SM9SigMasterPrivateKeyParameters(BigInteger.valueOf(0x77))
            .getPublicKeyParameters();
        Object[][] contexts = {
            { master.getPublicKeyParameters(), Strings.toByteArray("Bob"), "another identity" },
            { other, identity, "another master public key" } };
        for (int i = 0; i != contexts.length; i++)
        {
            try
            {
                SM9SigPrivateKeyParameters.fromEncoded(enc, (SM9SigMasterPublicKeyParameters)contexts[i][0],
                    (byte[])contexts[i][1]);
                fail("SM9 signature private key imported under " + contexts[i][2]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue(e.getMessage(),
                    "SM9 signature private key does not match its master public key and identity".equals(e.getMessage()));
            }
        }
    }

    /**
     * A key destroyed after init is reported through the CryptoException generateSignature declares,
     * not as the key's own IllegalStateException.
     */
    private void checkDestroyedKeyAtSign(SM9SigMasterPrivateKeyParameters master, byte[] identity, byte[] msg)
    {
        SM9SigPrivateKeyParameters key = master.generateUserKey(identity);
        SM9Signer signer = new SM9Signer();
        signer.init(true, new ParametersWithRandom(key, CryptoServicesRegistrar.getSecureRandom()));
        signer.update(msg, 0, msg.length);
        key.destroy();
        try
        {
            signer.generateSignature();
            fail("SM9Signer signed with a destroyed key");
        }
        catch (CryptoException e)
        {
            isTrue(e.getMessage(), "SM9 signing key destroyed".equals(e.getMessage()));
        }
    }

    // a signature over msg from a fresh signer initialised with params
    private static byte[] sign(CipherParameters params, byte[] msg)
        throws CryptoException
    {
        SM9Signer signer = new SM9Signer();
        signer.init(true, params);
        signer.update(msg, 0, msg.length);
        return signer.generateSignature();
    }

    /**
     * The curve order and the two group generators printed by the standard.
     */
    private void checkDomainParameters(Map v)
    {
        isTrue("SM9 curve order N", Arrays.areEqual(f32(SM9Curve.N), SM9Vectors.hex(v, "N")));

        ECPoint p1 = SM9Curve.P1.normalize();
        isTrue("SM9 generator P1.x",
            Arrays.areEqual(f32(p1.getAffineXCoord().toBigInteger()), SM9Vectors.hex(v, "P1x")));
        isTrue("SM9 generator P1.y",
            Arrays.areEqual(f32(p1.getAffineYCoord().toBigInteger()), SM9Vectors.hex(v, "P1y")));

        // G2 points serialize as 0x04 || x_hi || x_lo || y_hi || y_lo, each F_p2
        // coordinate high-dimension (u-coefficient) first
        isTrue("SM9 generator P2", Arrays.areEqual(SM9Curve.P2.getEncoded(),
            SM9Vectors.g2(v, "P2x_hi", "P2x_lo", "P2y_hi", "P2y_lo")));
    }

    /**
     * The KGC derivation chain: the signature master public key P_pub-s = [ks]P2
     * and the user's signing key ds_A = [t2]P1.
     */
    private void checkKeyDerivation(Map v, SM9SigMasterPrivateKeyParameters master,
                                    SM9SigPrivateKeyParameters userKey)
    {
        isTrue("SM9 master public key Ppub-s", Arrays.areEqual(
            master.getPublicKeyParameters().getEncoded(),
            SM9Vectors.g2(v, "Ppubsx_hi", "Ppubsx_lo", "Ppubsy_hi", "Ppubsy_lo")));

        ECPoint ds = userKey.getPrivatePoint().normalize();
        isTrue("SM9 user signing key dsA.x",
            Arrays.areEqual(f32(ds.getAffineXCoord().toBigInteger()), SM9Vectors.hex(v, "dsAx")));
        isTrue("SM9 user signing key dsA.y",
            Arrays.areEqual(f32(ds.getAffineYCoord().toBigInteger()), SM9Vectors.hex(v, "dsAy")));
    }

    /**
     * A verifier checks a signature against the identity it was initialised with, which it reads only
     * when verifySignature runs, whatever the caller does with its own array in between.
     */
    private void checkIdentityCopied(SM9SigMasterPrivateKeyParameters master, byte[] identity,
                                     byte[] msg, byte[] sig)
    {
        byte[] other = Arrays.clone(identity);
        other[0] ^= 0x01;

        // initialised for another identity, then the caller's array rewritten to the signer's
        byte[] buf = Arrays.clone(other);
        SM9Signer verifier = new SM9Signer();
        verifier.init(false, new ParametersWithID(master.getPublicKeyParameters(), buf));
        System.arraycopy(identity, 0, buf, 0, buf.length);
        verifier.update(msg, 0, msg.length);
        isTrue("a verifier initialised for another identity still refuses the signature after the caller's array changes",
            !verifier.verifySignature(sig));

        // and the other way round: initialised for the signer's identity, then the array rewritten
        buf = Arrays.clone(identity);
        verifier.init(false, new ParametersWithID(master.getPublicKeyParameters(), buf));
        System.arraycopy(other, 0, buf, 0, buf.length);
        verifier.update(msg, 0, msg.length);
        isTrue("a verifier initialised for the signer's identity still takes the signature after the caller's array changes",
            verifier.verifySignature(sig));
    }

    /**
     * Parameters of the wrong kind are named in an IllegalArgumentException, as SM9Engine names the
     * key it needs, and a signer used before init says so with an IllegalStateException.
     */
    private void checkMisuse(SM9SigMasterPrivateKeyParameters master, SM9SigPrivateKeyParameters userKey,
                             byte[] identity, byte[] sig)
        throws Exception
    {
        try
        {
            new SM9Signer().verifySignature(sig);
            fail("SM9Signer verified before init");
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9Signer not initialised for verification".equals(e.getMessage()));
        }
        try
        {
            new SM9Signer().generateSignature();
            fail("SM9Signer signed before init");
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9Signer not initialised for signing".equals(e.getMessage()));
        }

        checkInitRefused(true, new CipherParameters[]{ master.getPublicKeyParameters(),
            new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x77)).generateUserKey(identity,
                SM9EncMasterPrivateKeyParameters.HID) }, "SM9 signing requires an SM9SigPrivateKeyParameters user key");
        checkInitRefused(false, new CipherParameters[]{ new ParametersWithID(userKey, identity) },
            "SM9 verification requires an SM9SigMasterPublicKeyParameters master public key");
    }

    // each of params refused by init(forSigning, ...) of a fresh signer in the words given
    private void checkInitRefused(boolean forSigning, CipherParameters[] params, String message)
    {
        for (int i = 0; i != params.length; i++)
        {
            try
            {
                new SM9Signer().init(forSigning, params[i]);
                fail("SM9Signer took parameters " + i + ", " + params[i].getClass().getName() + ", for "
                    + (forSigning ? "signing" : "verification"));
            }
            catch (IllegalArgumentException e)
            {
                isTrue(message.equals(e.getMessage()));
            }
        }
    }

    /**
     * ParametersWithID goes outside ParametersWithRandom, the order the crypto.params package
     * documentation gives and SM2Signer takes, and the random source is unwrapped only for signing.
     * A chain nested the other way round, or carrying the same wrapper twice, is refused as a key of
     * the wrong kind rather than taken with one of its values unused.
     */
    private void checkWrapperNesting(SM9SigMasterPrivateKeyParameters master, SM9SigPrivateKeyParameters userKey,
                                     byte[] identity, byte[] msg)
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        SM9SigMasterPublicKeyParameters mpk = master.getPublicKeyParameters();

        byte[] sig = sign(new ParametersWithID(new ParametersWithRandom(userKey, random), identity), msg);
        isTrue("SM9 signing takes ParametersWithID outside ParametersWithRandom", verify(mpk, identity, msg, sig));

        checkInitRefused(true, new CipherParameters[]{
            new ParametersWithRandom(new ParametersWithID(userKey, identity), random),
            new ParametersWithRandom(new ParametersWithRandom(userKey, random), random),
            new ParametersWithID(new ParametersWithID(userKey, identity), identity) },
            "SM9 signing requires an SM9SigPrivateKeyParameters user key");
        checkInitRefused(false, new CipherParameters[]{
            new ParametersWithRandom(new ParametersWithID(mpk, identity), random),
            new ParametersWithID(new ParametersWithRandom(mpk, random), identity),
            new ParametersWithID(new ParametersWithID(mpk, identity), Strings.toByteArray("Bob")) },
            "SM9 verification requires an SM9SigMasterPublicKeyParameters master public key");
    }

    /**
     * An init the signer refuses leaves it uninitialised: it neither signs under the key of the init
     * before it nor verifies against that init's master public key.
     */
    private void checkRefusedInit(SM9SigMasterPrivateKeyParameters master, SM9SigPrivateKeyParameters userKey,
                                  byte[] identity, byte[] msg, byte[] sig)
        throws Exception
    {
        SM9Signer signer = new SM9Signer();
        signer.init(true, new ParametersWithRandom(userKey, CryptoServicesRegistrar.getSecureRandom()));
        try
        {
            signer.init(true, master.getPublicKeyParameters());
            fail("SM9Signer took a master public key for signing");
        }
        catch (IllegalArgumentException e)
        {
            // refused, as it should be - what matters is what the signer does next
        }
        signer.update(msg, 0, msg.length);
        try
        {
            signer.generateSignature();
            fail("SM9Signer signed after a refused init, under the key of the init before it");
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9Signer not initialised for signing".equals(e.getMessage()));
        }

        // refused for want of an identity, and for a key of the wrong kind
        CipherParameters[] refused = { master.getPublicKeyParameters(), new ParametersWithID(userKey, identity) };
        for (int i = 0; i != refused.length; i++)
        {
            SM9Signer verifier = new SM9Signer();
            verifier.init(false, new ParametersWithID(master.getPublicKeyParameters(), identity));
            try
            {
                verifier.init(false, refused[i]);
                fail("SM9Signer took " + refused[i].getClass().getName() + " for verification");
            }
            catch (IllegalArgumentException e)
            {
                // refused, as it should be
            }
            verifier.update(msg, 0, msg.length);
            try
            {
                verifier.verifySignature(sig);
                fail("SM9Signer verified after a refused init, against the key of the init before it");
            }
            catch (IllegalStateException e)
            {
                isTrue("SM9Signer not initialised for verification".equals(e.getMessage()));
            }
        }
    }

    /**
     * The message goes into H2, first in M || w, as update() is given it. With the vector's r, whose w
     * the standard prints, one signer and one verifier, each used again, sign and verify messages of 0
     * to 130 bytes and a few longer - putting the ends of w, of the counter and of the padding at every
     * offset in SM3's blocks - given in one call, a byte at a time or in pieces, each signature
     * carrying h = H2(M || w, N). Taking H2 up from the state a message leaves gives the same value
     * twice and leaves that state as it was; the digest, SM3Digest's words and expansion included,
     * where its reset() does not reach, holds nothing of a message once it is signed, verified or
     * reset, or the signer initialised again; and update() refuses a range outside its array.
     */
    private void checkMessageHashedAsGiven(Map v, SM9SigMasterPrivateKeyParameters master,
                                           SM9SigPrivateKeyParameters userKey, byte[] identity, byte[] msg, byte[] sig)
        throws Exception
    {
        SM9SigMasterPublicKeyParameters mpk = master.getPublicKeyParameters();
        byte[] r = SM9Vectors.hex(v, "r");
        byte[] w = SM9Vectors.hex(v, "w_GT");
        String[] how = { "in one call", "a byte at a time", "in pieces" };

        int[] extra = { 1000, 4096 + 7, 64 * 10 + 55, 20000 };
        int[] lengths = new int[131 + extra.length];
        for (int i = 0; i != lengths.length; i++)
        {
            lengths[i] = (i <= 130) ? i : extra[i - 131];
        }

        // one signer, drawing the vector's r for every signature, and one verifier
        byte[] rs = new byte[r.length * (lengths.length + 1)];
        for (int i = 0; i != lengths.length + 1; i++)
        {
            System.arraycopy(r, 0, rs, i * r.length, r.length);
        }
        SM9Signer signer = new SM9Signer();
        signer.init(true, new ParametersWithRandom(userKey, new FixedSecureRandom(rs)));
        SM9Signer verifier = new SM9Signer();
        verifier.init(false, new ParametersWithID(mpk, identity));

        give(signer, msg, 1);
        isTrue("SM9 signature over the vector's message given a byte at a time",
            Arrays.areEqual(signer.generateSignature(), sig));
        for (int i = 0; i != lengths.length; i++)
        {
            byte[] m = new byte[lengths[i]];
            for (int j = 0; j != m.length; j++)
            {
                m[j] = (byte)(j * 31 + m.length);
            }
            give(signer, m, i % 3);
            byte[] mSig = signer.generateSignature();
            isTrue("SM9 signature over " + m.length + " bytes given " + how[i % 3] + " carries H2(M || w, N)",
                Arrays.areEqual(Arrays.copyOfRange(mSig, 0, 32),
                    BigIntegers.asUnsignedByteArray(32, SM9Sm3.h2(Arrays.concatenate(m, w), SM9Curve.N))));
            give(verifier, m, (i + 1) % 3);
            isTrue("SM9 signature over " + m.length + " bytes verifies", verifier.verifySignature(mSig));
        }

        // H2 taken up twice from the message's state, with another w and then the vector's
        java.lang.reflect.Method h2 = declaredMethod(SM9Signer.class, "h2", new Class[]{ byte[].class });
        byte[] otherW = Arrays.clone(w);
        otherW[100] ^= 0x01;
        SM9Signer again = new SM9Signer();
        again.init(true, new ParametersWithRandom(userKey, new FixedSecureRandom(r)));
        again.update(msg, 0, msg.length);
        isTrue("H2 taken up from the message's state with another w",
            SM9Sm3.h2(Arrays.concatenate(msg, otherW), SM9Curve.N).equals(h2.invoke(again, new Object[]{ otherW })));
        isTrue("H2 taken up from the message's state again, with the vector's w",
            new BigInteger(1, SM9Vectors.hex(v, "h")).equals(h2.invoke(again, new Object[]{ w })));
        isTrue("H2 taken up twice leaves the message's state as it was", Arrays.areEqual(again.generateSignature(), sig));

        // nothing of a message stays in the digest once it is consumed, however it is
        byte[] longer = new byte[200];
        for (int j = 0; j != longer.length; j++)
        {
            longer[j] = (byte)(j + 1);
        }
        SM9Signer consumed = new SM9Signer();
        consumed.update(longer, 0, longer.length);
        isTrue("the digest holds the message given it", !holdsNothing(consumed));
        consumed.init(true, new ParametersWithRandom(userKey, new FixedSecureRandom(r)));
        isTrue("the digest holds nothing of the message once the signer is initialised", holdsNothing(consumed));
        consumed.update(longer, 0, longer.length);
        consumed.reset();
        isTrue("the digest holds nothing of the message once reset", holdsNothing(consumed));
        give(consumed, msg, 2);
        isTrue("a message given before init and one reset are dropped", Arrays.areEqual(consumed.generateSignature(), sig));
        isTrue("the digest holds nothing of the message once signed", holdsNothing(consumed));
        SM9Signer checked = new SM9Signer();
        checked.init(false, new ParametersWithID(mpk, identity));
        checked.update(longer, 0, longer.length);
        isTrue("the verifier's digest holds the message given it", !holdsNothing(checked));
        isTrue("a signature over another message does not verify", !checked.verifySignature(sig));
        isTrue("the digest holds nothing of the message once verified", holdsNothing(checked));

        // a range outside the array is refused, and nothing of it taken
        SM9Signer ranged = new SM9Signer();
        ranged.init(true, new ParametersWithRandom(userKey, new FixedSecureRandom(r)));
        ranged.update(msg, 0, 7);
        int[][] ranges = { { 0, -1 }, { -1, 1 }, { 7, msg.length }, { msg.length + 1, 0 } };
        for (int i = 0; i != ranges.length; i++)
        {
            try
            {
                ranged.update(msg, ranges[i][0], ranges[i][1]);
                fail("SM9Signer.update took " + ranges[i][1] + " bytes at " + ranges[i][0] + " of " + msg.length);
            }
            catch (IndexOutOfBoundsException e)
            {
                // refused, as it should be - what matters is that the message is as it was
            }
        }
        ranged.update(msg, 7, msg.length - 7);
        isTrue("an update refused for its range leaves the message as it was", Arrays.areEqual(ranged.generateSignature(), sig));
    }

    // the message given in one call, a byte at a time, or in pieces of 1, 2, ..., 67, 1, 2, ... bytes
    private static void give(SM9Signer signer, byte[] m, int how)
    {
        if (how == 0)
        {
            signer.update(m, 0, m.length);
        }
        else if (how == 1)
        {
            for (int i = 0; i != m.length; i++)
            {
                signer.update(m[i]);
            }
        }
        else
        {
            int off = 0;
            for (int len = 1; off < m.length; len = len % 67 + 1)
            {
                int n = Math.min(len, m.length - off);
                signer.update(m, off, n);
                off += n;
            }
        }
    }

    /**
     * Whether a signer's digest holds H2's prefix 0x02 and nothing else: the words of the block it
     * is filling and of the last it compressed, and that block's expansion, all zero.
     */
    private static boolean holdsNothing(SM9Signer signer)
        throws Exception
    {
        Object digest = declaredField(SM9Signer.class, "digest").get(signer);
        int[] words = (int[])declaredField(SM3Digest.class, "inwords").get(digest);
        int[] expansion = (int[])declaredField(SM3Digest.class, "W").get(digest);
        byte[] partial = (byte[])declaredField(GeneralDigest.class, "xBuf").get(digest);
        return Nat.isZero(words.length, words) && Nat.isZero(expansion.length, expansion)
            && partial[0] == 0x02 && Arrays.areAllZeroes(partial, 1, partial.length - 1);
    }

    private static java.lang.reflect.Field declaredField(Class c, String name)
        throws Exception
    {
        java.lang.reflect.Field f = c.getDeclaredField(name);
        f.setAccessible(true);
        return f;
    }

    /**
     * The signature master scalar is taken only in [1, N-1], whether constructed or decoded, and
     * decodes only at the 32 bytes getEncoded() writes, as the encryption master scalar does.
     */
    private void checkMasterScalar()
    {
        BigInteger[] outOfRange = { BigInteger.ZERO, SM9Curve.N, SM9Curve.N.add(BigInteger.ONE), BigInteger.valueOf(-1) };
        for (int i = 0; i != outOfRange.length; i++)
        {
            try
            {
                new SM9SigMasterPrivateKeyParameters(outOfRange[i]);
                fail("a signature master scalar of " + outOfRange[i] + " was taken");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("ks must be in [1, N-1]".equals(e.getMessage()));
            }
        }

        byte[] encoding = new SM9SigMasterPrivateKeyParameters(BigInteger.valueOf(0x4321)).getEncoded();
        isTrue("a 32-byte signature master scalar decodes",
            SM9SigMasterPrivateKeyParameters.fromEncoded(encoding) != null);
        // N itself, then encodings of the wrong length
        byte[][] undecodable = { BigIntegers.asUnsignedByteArray(32, SM9Curve.N), Arrays.copyOfRange(encoding, 1, 32),
            Arrays.prepend(encoding, (byte)0x00), new byte[]{ 0x43, 0x21 } };
        for (int i = 0; i != undecodable.length; i++)
        {
            try
            {
                SM9SigMasterPrivateKeyParameters.fromEncoded(undecodable[i]);
                fail("a signature master scalar decoded from " + undecodable[i].length + " bytes, encoding " + i);
            }
            catch (IllegalArgumentException e)
            {
                isTrue((i == 0 ? "ks must be in [1, N-1]" : "SM9 master private key must be 32 bytes")
                    .equals(e.getMessage()));
            }
        }

        // a scalar decoded alone agrees with the public key it derives, so it is held to the one the
        // KGC published, which tells a stale or substituted scalar from the KGC's
        SM9SigMasterPublicKeyParameters published =
            new SM9SigMasterPrivateKeyParameters(BigInteger.valueOf(0x4321)).getPublicKeyParameters();
        isTrue("a master scalar rebuilds against its own public key", Arrays.areEqual(encoding,
            SM9SigMasterPrivateKeyParameters.fromEncoded(encoding, published).getEncoded()));
        try
        {
            SM9SigMasterPrivateKeyParameters.fromEncoded(
                new SM9SigMasterPrivateKeyParameters(BigInteger.valueOf(0x4322)).getEncoded(), published);
            fail("a master scalar rebuilt against another key's public key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 master private key does not match its master public key".equals(e.getMessage()));
        }
    }

    /**
     * A signature whose S carries a coordinate at or above the field prime is invalid, and
     * verifySignature says so by answering false rather than letting the decoder's exception out.
     */
    private void checkOutOfFieldS(SM9SigMasterPrivateKeyParameters master, byte[] identity, byte[] msg, byte[] sig)
    {
        byte[] outOfField = Arrays.clone(sig);
        System.arraycopy(BigIntegers.asUnsignedByteArray(32, SM9Curve.G1.getField().getCharacteristic()),
            0, outOfField, 33, 32);
        isTrue("a signature with S's x at the field prime does not verify",
            !verify(master.getPublicKeyParameters(), identity, msg, outOfField));
    }

    /**
     * The nonce r is drawn from [1, N-1], a draw outside it drawn again, and a source that yields
     * nothing usable - only zeros, or only ones - is refused once the draws allowed are used up,
     * rather than hanging or having a fallback value stand in for r. The sources run out after 256
     * draws, so that a draw without a bound fails the test rather than hanging it.
     */
    private void checkUnusableSource(SM9SigPrivateKeyParameters userKey, byte[] msg)
    {
        for (int fill = 0x00; fill <= 0xFF; fill += 0xFF)
        {
            byte[] source = new byte[32 * 256];
            Arrays.fill(source, (byte)fill);
            SM9Signer signer = new SM9Signer();
            signer.init(true, new ParametersWithRandom(userKey, new FixedSecureRandom(source)));
            signer.update(msg, 0, msg.length);
            try
            {
                signer.generateSignature();
                fail("SM9Signer signed with a source that yields only 0x" + Integer.toHexString(fill));
            }
            catch (CryptoException e)
            {
                isTrue("SM9 signing could not draw a usable nonce".equals(e.getMessage()));
            }
        }
    }

    /**
     * The master private key is drawn from [1, N-1] as the nonce is: a draw outside it is discarded
     * and the next one taken, and a source that yields only zeros, or only ones, is refused once the
     * draws allowed are used up. The sources run out after 256 draws, twice the number allowed.
     */
    private void checkUnusableMasterSource()
    {
        byte[] ks = BigIntegers.asUnsignedByteArray(32, BigInteger.valueOf(0x4321));
        byte[] redrawn = Arrays.concatenate(new byte[32], BigIntegers.asUnsignedByteArray(32, SM9Curve.N), ks);
        SM9SigMasterKeyPairGenerator kpGen = new SM9SigMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(new FixedSecureRandom(redrawn), 256));
        isTrue("the signature master key is the first draw in [1, N-1]", Arrays.areEqual(ks,
            ((SM9SigMasterPrivateKeyParameters)kpGen.generateKeyPair().getPrivate()).getEncoded()));

        for (int fill = 0x00; fill <= 0xFF; fill += 0xFF)
        {
            byte[] source = new byte[32 * 256];
            Arrays.fill(source, (byte)fill);
            kpGen.init(new KeyGenerationParameters(new FixedSecureRandom(source), 256));
            try
            {
                kpGen.generateKeyPair();
                fail("SM9SigMasterKeyPairGenerator drew a key from a source that yields only 0x" + Integer.toHexString(fill));
            }
            catch (IllegalStateException e)
            {
                isTrue("SM9 master key generation could not draw a usable key".equals(e.getMessage()));
            }
        }
    }

    /**
     * An empty identity is refused for verification, as the KGC refuses to derive a key for one.
     */
    private void checkEmptyIdentity(SM9SigMasterPrivateKeyParameters master)
    {
        checkInitRefused(false, new CipherParameters[]{ new ParametersWithID(master.getPublicKeyParameters(),
            new byte[0]) }, "identity cannot be empty");
    }

    // the element of F_q eight limbs stand for as Fp holds one, in the form x R mod q, R = 2^256
    private static BigInteger fqValue(int[] limbs)
    {
        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        return Nat.toBigInteger(8, limbs).multiply(BigInteger.ONE.shiftLeft(256).modInverse(q)).mod(q);
    }

    /**
     * The exported math entry points refuse the scalars and exponents they cannot honour - over-wide
     * or negative - and bases off G1, the G2 point at infinity has no encoding to give, and zero has
     * no inverse in the G1 field or in the pairing tower.
     */
    private void checkMathEntryPointRanges()
        throws Exception
    {
        BigInteger tooWide = BigInteger.ONE.shiftLeft(SM9Curve.N.bitLength());
        BigInteger negative = BigInteger.valueOf(-1);
        Fp12 g = SM9Pairing.pairing(SM9Curve.P1, SM9Curve.P2);

        BigInteger[] badScalars = { tooWide, negative };
        for (int i = 0; i != badScalars.length; i++)
        {
            try
            {
                SM9Curve.P2.multiply(badScalars[i]);
                fail("SM9G2Point.multiply accepted an out-of-range scalar");
            }
            catch (IllegalArgumentException e)
            {
                // the message is asserted: any other IllegalArgumentException out of the ladder would pass
                isTrue("SM9G2Point.multiply scalar message: " + e.getMessage(),
                    "scalar must be non-negative and at most 256 bits".equals(e.getMessage()));
            }
            checkG1EntryPointsRefuse(SM9Curve.P1, badScalars[i], BigInteger.ONE, true);
            try
            {
                g.powSecure(badScalars[i]);
                fail("Fp12.powSecure accepted an out-of-range exponent");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("exponent must be in the range [0, N)".equals(e.getMessage()));
            }
            try
            {
                g.powSecureFixedBase(badScalars[i]);
                fail("Fp12.powSecureFixedBase accepted an out-of-range exponent");
            }
            catch (IllegalArgumentException e)
            {
                isTrue("exponent must be in the range [0, N)".equals(e.getMessage()));
            }
        }
        try
        {
            g.pow(negative);
            fail("Fp12.pow accepted a negative exponent");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("exponent must be non-negative".equals(e.getMessage()));
        }

        // a base off G1 is refused: the comb, blinding the scalar with multiples of this curve's order,
        // would return a wrong multiple of a point of another curve
        ECPoint[] badBases = { CustomNamedCurves.getByName("P-256").getG(),
            SM9Curve.G1.createPoint(BigInteger.ONE, BigInteger.ONE) };
        for (int i = 0; i != badBases.length; i++)
        {
            checkG1EntryPointsRefuse(badBases[i], BigInteger.valueOf(2), BigInteger.valueOf(2), false);
        }

        // and the values in range are unaffected
        isTrue("the generator still multiplies", !SM9Curve.P2.multiply(SM9Curve.N.subtract(
            BigInteger.ONE)).isInfinity());
        isTrue("the pairing value still exponentiates",
            g.powSecure(SM9Curve.N.subtract(BigInteger.ONE)).equals(g.pow(SM9Curve.N.subtract(BigInteger.ONE))));
        isTrue("the pairing value still exponentiates through the comb",
            g.powSecureFixedBase(SM9Curve.N.subtract(BigInteger.ONE)).equals(g.pow(SM9Curve.N.subtract(BigInteger.ONE))));

        try
        {
            SM9Curve.P2.multiply(SM9Curve.N).getEncoded();
            fail("SM9G2Point encoded the point at infinity");
        }
        catch (IllegalStateException e)
        {
            isTrue("SM9 G2 point at infinity has no uncompressed encoding".equals(e.getMessage()));
        }

        // zero has no inverse in the G1 field, through invert() or divide()
        ECFieldElement zero = SM9Curve.G1.fromBigInteger(BigInteger.ZERO);
        ECFieldElement five = SM9Curve.G1.fromBigInteger(BigInteger.valueOf(5));
        try
        {
            zero.invert();
            fail("SM9 G1 field inverted zero");
        }
        catch (ArithmeticException e)
        {
            isTrue("Inverse does not exist.".equals(e.getMessage()));
        }
        try
        {
            five.divide(zero);
            fail("SM9 G1 field divided by zero");
        }
        catch (ArithmeticException e)
        {
            isTrue("Inverse does not exist.".equals(e.getMessage()));
        }
        isTrue("a non-zero SM9 G1 field element still inverts", five.invert().multiply(five).isOne());

        // nor in the pairing tower, whose package-private F_p2, F_p4 and F_p12 say so in the same words
        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        Class fp4 = Class.forName("org.bouncycastle.math.ec.sm9.Fp4");
        Object fp2Zero = staticField(fp2, "ZERO");
        Object fp4Zero = staticField(fp4, "ZERO");
        java.lang.reflect.Constructor fp12 = Fp12.class.getDeclaredConstructor(new Class[]{ fp4, fp4, fp4 });
        fp12.setAccessible(true);
        Object[] zeros = { fp2Zero, fp4Zero, fp12.newInstance(new Object[]{ fp4Zero, fp4Zero, fp4Zero }) };
        for (int i = 0; i != zeros.length; i++)
        {
            java.lang.reflect.Method invert = declaredMethod(zeros[i].getClass(), "invert", new Class[0]);
            try
            {
                invert.invoke(zeros[i], new Object[0]);
                fail(zeros[i].getClass().getName() + " inverted zero");
            }
            catch (java.lang.reflect.InvocationTargetException e)
            {
                isTrue(zeros[i].getClass().getName() + " refuses to invert zero",
                    e.getTargetException() instanceof ArithmeticException
                        && "Inverse does not exist.".equals(e.getTargetException().getMessage()));
            }
        }
    }

    // multiplySecure, sumOfTwoMultipliesSecure with (b, k) as its first pair and then as its second
    // beside (P1, other), and multiplyPublic each refuse base b with scalar k, for the scalar if
    // badScalar is set and otherwise for the base
    private void checkG1EntryPointsRefuse(ECPoint b, BigInteger k, BigInteger other, boolean badScalar)
    {
        for (int j = 0; j != 4; j++)
        {
            try
            {
                if (j == 0)
                {
                    SM9Curve.multiplySecure(b, k);
                }
                else if (j == 3)
                {
                    SM9Curve.multiplyPublic(b, k);
                }
                else
                {
                    SM9Curve.sumOfTwoMultipliesSecure((j == 1) ? b : SM9Curve.P1, (j == 1) ? k : other,
                        (j == 2) ? b : SM9Curve.P1, (j == 2) ? k : other);
                }
                fail("SM9Curve's G1 entry point " + j + " took " + (badScalar ? "the scalar " + k : "a base off G1"));
            }
            catch (IllegalArgumentException e)
            {
                if (badScalar)
                {
                    isTrue("scalar message names the scalar", e.getMessage().startsWith("scalar must be non-negative"));
                }
                else
                {
                    isTrue("base point is not a point of SM9's G1".equals(e.getMessage()));
                }
            }
        }
    }

    /**
     * The G1 curve's random field elements are field elements - below q, and non-zero where asked -
     * as ECPoint.normalize() blinds every inversion with one.
     */
    private void checkRandomFieldElements()
    {
        java.security.SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        for (int i = 0; i != 64; i++)
        {
            ECFieldElement m = SM9Curve.G1.randomFieldElementMult(random);
            isTrue("a random multiplier is a non-zero field element",
                !m.isZero() && m.toBigInteger().compareTo(q) < 0 && m.multiply(m.invert()).isOne());
            isTrue("a random field element is below q",
                SM9Curve.G1.randomFieldElement(random).toBigInteger().compareTo(q) < 0);
        }
    }

    /**
     * The G1 field against BigInteger arithmetic mod q. Its limbs hold the Montgomery form x R mod q
     * and each sum, difference and product is brought below q by a masked subtraction of q, so the
     * edges below, which put the value it reduces on either side of q or past 2^256, are taken as
     * values and, through e R^-1 mod q, as forms, in every pair, besides random values. Each result
     * must also equal the element built from the expected value, as it does only if reduced below q.
     */
    private void checkG1FieldArithmetic()
    {
        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        BigInteger two = BigInteger.valueOf(2);
        BigInteger[] edges = { BigInteger.ZERO, BigInteger.ONE, two, q.subtract(BigInteger.ONE),
            q.subtract(two), q.shiftRight(1), q.shiftRight(1).add(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(255), BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(256).subtract(q), BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE),
            q.subtract(BigInteger.ONE.shiftLeft(32)) };
        BigInteger rInv = BigInteger.ONE.shiftLeft(256).modInverse(q);
        BigInteger[] values = new BigInteger[2 * edges.length];
        for (int i = 0; i != edges.length; i++)
        {
            values[i] = edges[i];
            values[edges.length + i] = edges[i].multiply(rInv).mod(q);
        }
        for (int i = 0; i != values.length; i++)
        {
            for (int j = 0; j != values.length; j++)
            {
                checkG1FieldOps(q, values[i], values[j]);
            }
        }
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        for (int i = 0; i != 500; i++)
        {
            checkG1FieldOps(q, BigIntegers.createRandomBigInteger(256, random).mod(q),
                BigIntegers.createRandomBigInteger(256, random).mod(q));
        }
    }

    private void checkG1FieldOps(BigInteger q, BigInteger a, BigInteger b)
    {
        ECFieldElement x = SM9Curve.G1.fromBigInteger(a);
        ECFieldElement y = SM9Curve.G1.fromBigInteger(b);
        checkG1Element("x + y", x.add(y), a.add(b).mod(q), a, b);
        checkG1Element("x - y", x.subtract(y), a.subtract(b).mod(q), a, b);
        checkG1Element("x * y", x.multiply(y), a.multiply(b).mod(q), a, b);
        checkG1Element("x^2", x.square(), a.multiply(a).mod(q), a, b);
        checkG1Element("-x", x.negate(), a.negate().mod(q), a, b);
        checkG1Element("x + 1", x.addOne(), a.add(BigInteger.ONE).mod(q), a, b);
        if (a.signum() != 0)
        {
            checkG1Element("x^-1", x.invert(), a.modInverse(q), a, b);
        }
        if (b.signum() != 0)
        {
            checkG1Element("x / y", x.divide(y), a.multiply(b.modInverse(q)).mod(q), a, b);
        }
    }

    private void checkG1Element(String op, ECFieldElement got, BigInteger want, BigInteger a, BigInteger b)
    {
        if (!got.toBigInteger().equals(want) || !got.equals(SM9Curve.G1.fromBigInteger(want)))
        {
            fail("SM9 G1 field: " + op + " for x = " + a.toString(16) + ", y = " + b.toString(16));
        }
    }

    /**
     * The extension fields' wide arithmetic against BigInteger: Fp.reduceWide to x R^-1 mod q, below q,
     * over its range |x| &lt; 2^520 - at its ends, at 0, 1, 2^512 and q^2 and their negatives, beside
     * the multiples of q R, where the quotient by q it estimates is at or next to an integer, and at
     * random; Fp.mulWide, Fp.sqrWide and Fp.combine to the products and sums in full, the latter up to
     * the ends of reduceWide's range and written over its first operand as well; and the products and
     * squares of F_p2, F_p4 and F_p12, the cyclotomic squaring with a factor and without, the sparse
     * product and Karabina's compressed squaring to the tower model below, on coefficients whose forms
     * are 0 or q - 1 in random patterns (taking the sums of products to the ends of their ranges),
     * edges of the field or random, written over an operand where they may be, and on scratch whose
     * every word is all ones, so that one that reads a limb it has not written fails.
     */
    private void checkTowerArithmetic()
        throws Exception
    {
        Class fp = Class.forName("org.bouncycastle.math.ec.sm9.Fp");
        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        Class fp4 = Class.forName("org.bouncycastle.math.ec.sm9.Fp4");
        Class a = int[].class, i = int.class, l = long.class;
        java.lang.reflect.Method reduceWide = declaredMethod(fp, "reduceWide", new Class[]{ a, i, a, i });
        java.lang.reflect.Method mulWide = declaredMethod(fp, "mulWide", new Class[]{ a, i, a, i, a, i });
        java.lang.reflect.Method sqrWide = declaredMethod(fp, "sqrWide", new Class[]{ a, i, a, i });
        java.lang.reflect.Method[] combine = {
            declaredMethod(fp, "combine", new Class[]{ a, i, l, a, i }),
            declaredMethod(fp, "combine", new Class[]{ a, i, l, i, l, a, i }),
            declaredMethod(fp, "combine", new Class[]{ a, i, l, i, l, i, l, a, i }),
            declaredMethod(fp, "combine", new Class[]{ a, i, l, i, l, i, l, i, l, a, i }),
            declaredMethod(fp, "combine", new Class[]{ a, i, l, i, l, i, l, i, l, i, l, a, i }) };
        Class[] product = { a, i, a, i, a, i, a, i }, square = { a, i, a, i, a, i };
        java.lang.reflect.Method mul2 = declaredMethod(fp2, "mul", product);
        java.lang.reflect.Method sqr2 = declaredMethod(fp2, "sqr", square);
        java.lang.reflect.Method mul4 = declaredMethod(fp4, "mul", product);
        java.lang.reflect.Method sqr4 = declaredMethod(fp4, "sqr", square);
        java.lang.reflect.Method mul12 = declaredMethod(Fp12.class, "mul", product);
        java.lang.reflect.Method sqr12 = declaredMethod(Fp12.class, "sqr", square);
        java.lang.reflect.Method cyclotomic = declaredMethod(Fp12.class, "cyclotomicSqr", product);
        java.lang.reflect.Method sparse = declaredMethod(Fp12.class, "mulSparse", new Class[]{ a, i, a, i, a, i, a, i,
            a, i });
        java.lang.reflect.Method compressed = declaredMethod(Fp12.class, "compressedSqr", square);
        int[] t = new int[Math.max(((Integer)staticField(Fp12.class, "MUL_SCRATCH")).intValue(),
            ((Integer)staticField(Fp12.class, "MUL_SPARSE_SCRATCH")).intValue())];
        Integer zero = Integers.valueOf(0);

        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        BigInteger r = BigInteger.ONE.shiftLeft(256), rInv = r.modInverse(q), qr = q.multiply(r);
        BigInteger limit = BigInteger.ONE.shiftLeft(520), two512 = BigInteger.ONE.shiftLeft(512);

        // reduceWide, over |x| < 2^520
        BigInteger[] ends = { BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE.negate(), limit.subtract(BigInteger.ONE),
            BigInteger.ONE.subtract(limit), two512, two512.negate(), two512.subtract(BigInteger.ONE),
            q.multiply(q), q.multiply(q).negate() };
        for (int j = 0; j != ends.length; j++)
        {
            checkReduceWide(reduceWide, q, rInv, ends[j]);
        }
        int multiples = limit.divide(qr).intValue();
        BigInteger[] nearby = { BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE.negate(), q, q.add(BigInteger.ONE),
            q.subtract(BigInteger.ONE), r, r.negate(), r.shiftLeft(1).negate() };
        for (int k = -multiples; k <= multiples; k++)
        {
            for (int j = 0; j != nearby.length; j++)
            {
                BigInteger x = qr.multiply(BigInteger.valueOf(k)).add(nearby[j]);
                if (x.abs().compareTo(limit) < 0)
                {
                    checkReduceWide(reduceWide, q, rInv, x);
                }
            }
        }
        for (int j = 0; j != 20000; j++)
        {
            BigInteger x = BigIntegers.createRandomBigInteger(1 + random.nextInt(519), random);
            checkReduceWide(reduceWide, q, rInv, random.nextBoolean() ? x : x.negate());
        }

        // mulWide and sqrWide
        BigInteger[] operands = { BigInteger.ZERO, BigInteger.ONE, q.subtract(BigInteger.ONE), r.subtract(BigInteger.ONE),
            BigIntegers.createRandomBigInteger(256, random), BigIntegers.createRandomBigInteger(256, random) };
        for (int j = 0; j != operands.length; j++)
        {
            for (int k = 0; k != operands.length; k++)
            {
                int[] zz = new int[17];
                mulWide.invoke(null, new Object[]{ Nat.fromBigInteger(256, operands[j]), zero,
                    Nat.fromBigInteger(256, operands[k]), zero, zz, zero });
                isTrue("Fp.mulWide gives the product in full",
                    Arrays.areEqual(zz, wide(operands[j].multiply(operands[k]))));
            }
            int[] zz = new int[17];
            sqrWide.invoke(null, new Object[]{ Nat.fromBigInteger(256, operands[j]), zero, zz, zero });
            isTrue("Fp.sqrWide gives the square in full", Arrays.areEqual(zz, wide(operands[j].multiply(operands[j]))));
        }

        // combine, of one to five wide values, into a fresh array and over its first operand
        for (int j = 0; j != 2000; j++)
        {
            int terms = 1 + j % 5;
            int[] v = new int[17 * terms];
            Object[] arguments = new Object[3 + 2 * terms];
            arguments[0] = v;
            BigInteger want = BigInteger.ZERO;
            for (int k = 0; k != terms; k++)
            {
                BigInteger x = j < 20 ? ((j / 5) % 2 == 0 ? limit.subtract(BigInteger.ONE) : BigInteger.ONE.subtract(limit))
                    : BigIntegers.createRandomBigInteger(1 + random.nextInt(519), random);
                if (j >= 20 && random.nextBoolean())
                {
                    x = x.negate();
                }
                long c = j < 20 ? (j < 10 ? 30 : -30) : random.nextInt(61) - 30;
                System.arraycopy(wide(x), 0, v, 17 * k, 17);
                arguments[1 + 2 * k] = Integers.valueOf(17 * k);
                arguments[2 + 2 * k] = Longs.valueOf(c);
                want = want.add(x.multiply(BigInteger.valueOf(c)));
            }
            int[] zz = new int[17];
            arguments[1 + 2 * terms] = zz;
            arguments[2 + 2 * terms] = zero;
            combine[terms - 1].invoke(null, arguments);
            isTrue("Fp.combine gives the sum of " + terms, Arrays.areEqual(zz, wide(want)));
            arguments[1 + 2 * terms] = v;
            combine[terms - 1].invoke(null, arguments);
            isTrue("Fp.combine gives the sum of " + terms + " over its first operand",
                Arrays.areEqual(Arrays.copyOfRange(v, 0, 17), wide(want)));
        }

        // the products and squares of the tower
        for (int j = 0; j != 600; j++)
        {
            int pattern = j % 3;
            int[] x = new int[96], y = new int[96], m = new int[8];
            BigInteger[] xv = towerElement(x, 12, pattern, q, rInv, random);
            BigInteger[] yv = towerElement(y, 12, pattern, q, rInv, random);
            BigInteger[] mv = towerElement(m, 1, pattern, q, rInv, random);
            String where = " for coefficients of pattern " + pattern;

            int[] z = new int[96];
            invokeOnOnes(mul2, t, new Object[]{ x, zero, y, zero, z, zero, t, zero });
            checkTower("F_p2 product" + where, z, 2, towerMul(q, part(xv, 0, 2), part(yv, 0, 2)), q);
            invokeOnOnes(sqr2, t, new Object[]{ x, zero, z, zero, t, zero });
            checkTower("F_p2 square" + where, z, 2, towerMul(q, part(xv, 0, 2), part(xv, 0, 2)), q);
            invokeOnOnes(mul4, t, new Object[]{ x, zero, y, zero, z, zero, t, zero });
            checkTower("F_p4 product" + where, z, 4, towerMul(q, part(xv, 0, 4), part(yv, 0, 4)), q);
            invokeOnOnes(sqr4, t, new Object[]{ x, zero, z, zero, t, zero });
            checkTower("F_p4 square" + where, z, 4, towerMul(q, part(xv, 0, 4), part(xv, 0, 4)), q);

            BigInteger[] want = towerMul(q, xv, yv);
            invokeOnOnes(mul12, t, new Object[]{ x, zero, y, zero, z, zero, t, zero });
            checkTower("F_p12 product" + where, z, 12, want, q);
            int[] over = Arrays.clone(y);
            invokeOnOnes(mul12, t, new Object[]{ x, zero, over, zero, over, zero, t, zero });
            checkTower("F_p12 product over its second operand" + where, over, 12, want, q);

            want = towerMul(q, xv, xv);
            over = Arrays.clone(x);
            invokeOnOnes(sqr12, t, new Object[]{ over, zero, over, zero, t, zero });
            checkTower("F_p12 square over its operand" + where, over, 12, want, q);

            over = Arrays.clone(x);
            invokeOnOnes(cyclotomic, t, new Object[]{ over, zero, null, zero, over, zero, t, zero });
            checkTower("F_p12 cyclotomic squaring" + where, over, 12, cyclotomicSquare(q, xv, BigInteger.ONE), q);
            over = Arrays.clone(x);
            invokeOnOnes(cyclotomic, t, new Object[]{ over, zero, m, zero, over, zero, t, zero });
            checkTower("F_p12 cyclotomic squaring with a factor" + where, over, 12, cyclotomicSquare(q, xv, mv[0]), q);

            BigInteger[] line = new BigInteger[12];
            System.arraycopy(yv, 0, line, 0, 4);
            System.arraycopy(yv, 4, line, 8, 2);
            for (int k = 0; k != 12; k++)
            {
                line[k] = line[k] == null ? BigInteger.ZERO : line[k];
            }
            over = Arrays.clone(x);
            invokeOnOnes(sparse, t, new Object[]{ over, zero, y, zero, y, Integers.valueOf(32), over, zero, t, zero });
            checkTower("F_p12 sparse product" + where, over, 12, towerMul(q, xv, line), q);

            over = Arrays.clone(x);
            invokeOnOnes(compressed, t, new Object[]{ over, zero, over, zero, t, zero });
            checkTower("F_p12 compressed squaring" + where, over, 8, compressedSquare(q, part(xv, 0, 8)), q);
        }
    }

    /**
     * The Miller loop's doubling and addition, the doublings and additions of G2 and G1 in Jacobian
     * coordinates and Karabina's decompression, which form their sums of products in full and reduce
     * each coefficient once, against the BigInteger models of their formulas below, on operands drawn
     * as checkTowerArithmetic draws them - so the points are on neither curve, which the formulas do
     * not need - on scratch whose every word is all ones, and written over their operands where they
     * may be. The addition of an affine point flags H = 0 and s = 0, that of two Jacobian points gives
     * either point where the other is at infinity, and the Miller loop's steps refuse a T they take to
     * Z = 0, and only such a T.
     */
    private void checkCurveArithmetic()
        throws Exception
    {
        Class g1 = Class.forName("org.bouncycastle.math.ec.sm9.SM9G1Multiplier");
        Class a = int[].class, i = int.class;
        java.lang.reflect.Method lineDouble = declaredMethod(SM9Pairing.class, "lineDouble", new Class[]{ a, a, i, a });
        java.lang.reflect.Method lineAdd = declaredMethod(SM9Pairing.class, "lineAdd", new Class[]{ a, a, a, a, i, a });
        java.lang.reflect.Method twice2 = declaredMethod(SM9G2Point.class, "twice", new Class[]{ a, a, a });
        java.lang.reflect.Method sum2 = declaredMethod(SM9G2Point.class, "sum", new Class[]{ a, a, i, a });
        java.lang.reflect.Method add2 = declaredMethod(SM9G2Point.class, "add", new Class[]{ a, a, a, a });
        java.lang.reflect.Method twice1 = declaredMethod(g1, "twice", new Class[]{ a, a, a });
        java.lang.reflect.Method sum1 = declaredMethod(g1, "sum", new Class[]{ a, a, i, a });
        java.lang.reflect.Method decompress = declaredMethod(Fp12.class, "decompress", new Class[]{ a, i });
        java.lang.reflect.Field limbs = declaredField(Fp12.class, "limbs");
        int lineScratch = ((Integer)staticField(SM9Pairing.class, "LINE_SCRATCH")).intValue();
        int scratch2 = ((Integer)staticField(SM9G2Point.class, "SCRATCH")).intValue();
        int sumAt2 = ((Integer)staticField(SM9G2Point.class, "SUM")).intValue();
        int scratch1 = ((Integer)staticField(g1, "SCRATCH")).intValue();
        int sumAt1 = ((Integer)staticField(g1, "SUM")).intValue();

        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        BigInteger rInv = BigInteger.ONE.shiftLeft(256).modInverse(q);
        for (int j = 0; j != 600; j++)
        {
            int pattern = j % 3;
            String where = " for coordinates of pattern " + pattern;

            // the Miller loop's doubling, T in place, its tangent written after a line already there
            int[] t = new int[48], l = new int[96], s = new int[lineScratch];
            BigInteger[] tv = towerElement(t, 6, pattern, q, rInv, random);
            BigInteger[] want = millerDouble(q, part(tv, 0, 2), part(tv, 2, 2), part(tv, 4, 2));
            boolean refused = refusesZ(lineDouble, s, new Object[]{ t, l, Integers.valueOf(48), s });
            isTrue("the Miller loop's doubling refuses T where it takes it to Z = 0, and only there" + where,
                refused == isZero(part(want, 4, 2)));
            if (!refused)
            {
                checkTower("the Miller loop's doubling" + where, t, 6, part(want, 0, 6), q);
                checkTower("the Miller loop's tangent" + where, Arrays.copyOfRange(l, 48, 96), 6, part(want, 6, 6), q);
            }

            // the Miller loop's addition of (x2, y2)
            int[] x2 = new int[16], y2 = new int[16];
            BigInteger[] x2v = towerElement(x2, 2, pattern, q, rInv, random);
            BigInteger[] y2v = towerElement(y2, 2, pattern, q, rInv, random);
            tv = towerElement(t, 6, pattern, q, rInv, random);
            want = millerAdd(q, part(tv, 0, 2), part(tv, 2, 2), part(tv, 4, 2), x2v, y2v);
            refused = refusesZ(lineAdd, s, new Object[]{ t, x2, y2, l, Integers.valueOf(0), s });
            isTrue("the Miller loop's addition refuses T where it takes it to Z = 0, and only there" + where,
                refused == isZero(part(want, 4, 2)));
            if (!refused)
            {
                checkTower("the Miller loop's addition" + where, t, 6, part(want, 0, 6), q);
                checkTower("the Miller loop's chord" + where, Arrays.copyOfRange(l, 0, 48), 6, part(want, 6, 6), q);
            }

            // the doubling, addition of an affine point, from an offset, and addition of Jacobian points
            // of G2 and of G1, into a fresh point and over their operands
            for (int k = 1; k <= 2; k++)
            {
                String group = k == 2 ? "G2 " : "G1 ";
                java.lang.reflect.Method twice = k == 2 ? twice2 : twice1, sum = k == 2 ? sum2 : sum1;
                int size = 8 * k, scratch = k == 2 ? scratch2 : scratch1, sumAt = k == 2 ? sumAt2 : sumAt1;
                int[] p = new int[3 * size], z = new int[3 * size], u = new int[scratch];
                BigInteger[] pv = towerElement(p, 3 * k, pattern, q, rInv, random);
                want = jacobianDouble(q, part(pv, 0, k), part(pv, k, k), part(pv, 2 * k, k));
                invokeOnOnes(twice, u, new Object[]{ p, z, u });
                checkTower(group + "doubling" + where, z, 3 * k, want, q);
                int[] over = Arrays.clone(p);
                invokeOnOnes(twice, u, new Object[]{ over, over, u });
                checkTower(group + "doubling over its operand" + where, over, 3 * k, want, q);

                int[] e = new int[4 * size];
                BigInteger[] ev = towerElement(e, 4 * k, pattern, q, rInv, random);
                BigInteger[] one = part(new BigInteger[]{ BigInteger.ONE, BigInteger.ZERO }, 0, k);
                want = jacobianAdd(q, pv, join(part(ev, 2 * k, 2 * k), one), k);
                int equal = ((Integer)invokeOnOnes(sum, u, new Object[]{ p, e, Integers.valueOf(2 * size), u }))
                    .intValue();
                checkTower(group + "addition of an affine point" + where, Arrays.copyOfRange(u, sumAt, sumAt + 3 * size),
                    3 * k, want, q);
                isTrue(group + "addition of an affine point flags H = 0 and s = 0" + where,
                    (equal == 1) == (isZero(part(want, 3 * k, k)) && isZero(part(want, 4 * k, k))));

                if (k == 2)
                {
                    int[] w = new int[48];
                    BigInteger[] wv = towerElement(w, 6, pattern, q, rInv, random);
                    want = part(jacobianAdd(q, pv, wv, 2), 0, 6);
                    want = isZero(part(wv, 4, 2)) ? pv : want;
                    want = isZero(part(pv, 4, 2)) ? wv : want;
                    invokeOnOnes(add2, u, new Object[]{ p, w, z, u });
                    checkTower("G2 addition" + where, z, 6, want, q);
                    over = Arrays.clone(p);
                    invokeOnOnes(add2, u, new Object[]{ over, w, over, u });
                    checkTower("G2 addition over its first operand" + where, over, 6, want, q);
                    over = Arrays.clone(w);
                    invokeOnOnes(add2, u, new Object[]{ p, over, over, u });
                    checkTower("G2 addition over its second operand" + where, over, 6, want, q);
                }
            }

            // the decompression of one to eleven elements, some with a g2 of 0 and some with a g2 and
            // a g3 of 0
            int count = 1 + random.nextInt(11);
            int[] c = new int[64 * count];
            BigInteger[] cv = towerElement(c, 8 * count, pattern, q, rInv, random);
            for (int k = 0; k != count; k++)
            {
                int zeros = random.nextInt(4);
                for (int m = 0; m < 2 * (zeros - 1); m++)
                {
                    Arrays.fill(c, 64 * k + 8 * m, 64 * k + 8 * m + 8, 0);
                    cv[8 * k + m] = BigInteger.ZERO;
                }
            }
            Object[] got = (Object[])decompress.invoke(null, new Object[]{ c, Integers.valueOf(count) });
            for (int k = 0; k != count; k++)
            {
                checkTower("decompression, element " + k + " of " + count + where, (int[])limbs.get(got[k]), 12,
                    decompressed(q, part(cv, 8 * k, 8)), q);
            }
        }
    }

    // whether m, invoked on the arguments with scratch all ones, refuses them as SM9Pairing refuses a
    // second argument that takes T to Z = 0
    private boolean refusesZ(java.lang.reflect.Method m, int[] scratch, Object[] arguments)
        throws Exception
    {
        try
        {
            invokeOnOnes(m, scratch, arguments);
            return false;
        }
        catch (java.lang.reflect.InvocationTargetException e)
        {
            Throwable cause = e.getTargetException();
            isTrue("refused as not a point of G2: " + cause, cause instanceof IllegalArgumentException
                && "SM9 pairing second argument is not a point of G2".equals(cause.getMessage()));
            return true;
        }
    }

    private static java.lang.reflect.Method declaredMethod(Class c, String name, Class[] parameters)
        throws Exception
    {
        java.lang.reflect.Method m = c.getDeclaredMethod(name, parameters);
        m.setAccessible(true);
        return m;
    }

    // the static m invoked on the arguments with every word of its scratch all ones, so that a read of
    // a limb it has not written shows
    private static Object invokeOnOnes(java.lang.reflect.Method m, int[] scratch, Object[] arguments)
        throws Exception
    {
        Arrays.fill(scratch, -1);
        return m.invoke(null, arguments);
    }

    // x as seventeen limbs, least significant first, in two's complement: a wide value
    private static int[] wide(BigInteger x)
    {
        return Nat.fromBigInteger(544, x.signum() < 0 ? x.add(BigInteger.ONE.shiftLeft(544)) : x);
    }

    private void checkReduceWide(java.lang.reflect.Method reduceWide, BigInteger q, BigInteger rInv, BigInteger x)
        throws Exception
    {
        int[] z = new int[8];
        reduceWide.invoke(null, new Object[]{ wide(x), Integers.valueOf(0), z, Integers.valueOf(0) });
        if (!Arrays.areEqual(z, Nat.fromBigInteger(256, x.multiply(rInv).mod(q))))
        {
            fail("Fp.reduceWide gives x R^-1 mod q, below q, for x = " + x.toString(16));
        }
    }

    // an element of F_q^count into x, its coefficients' forms chosen by the pattern - 0 or q - 1, or an
    // edge of the field, or random - and the values they stand for, form times R^-1 mod q
    private static BigInteger[] towerElement(int[] x, int count, int pattern, BigInteger q, BigInteger rInv,
        SecureRandom random)
    {
        BigInteger[] edges = { BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), q.subtract(BigInteger.ONE),
            q.subtract(BigInteger.valueOf(2)), q.shiftRight(1), q.shiftRight(1).add(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(255), BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(256).subtract(q), q.subtract(BigInteger.ONE.shiftLeft(32)) };
        BigInteger[] v = new BigInteger[count];
        for (int k = 0; k != count; k++)
        {
            BigInteger form;
            if (pattern == 0)
            {
                form = random.nextBoolean() ? q.subtract(BigInteger.ONE) : BigInteger.ZERO;
            }
            else if (pattern == 1)
            {
                form = edges[random.nextInt(edges.length)];
            }
            else
            {
                form = BigIntegers.createRandomBigInteger(256, random).mod(q);
            }
            System.arraycopy(Nat.fromBigInteger(256, form), 0, x, 8 * k, 8);
            v[k] = form.multiply(rInv).mod(q);
        }
        return v;
    }

    // whether z holds, as forms, the first count coefficients of want
    private void checkTower(String what, int[] z, int count, BigInteger[] want, BigInteger q)
    {
        BigInteger r = BigInteger.ONE.shiftLeft(256);
        for (int k = 0; k != count; k++)
        {
            if (!Arrays.areEqual(Arrays.copyOfRange(z, 8 * k, 8 * k + 8),
                Nat.fromBigInteger(256, want[k].multiply(r).mod(q))))
            {
                fail(what + " agrees with the model, coefficient " + k);
            }
        }
    }

    // the model of the tower over BigInteger: an element of F_p2 as its two coefficients, and one of
    // F_p4 or F_p12 as the coefficients of its two or three coefficients in turn, as Fp2, Fp4 and Fp12
    // hold them
    private static BigInteger[] towerMul(BigInteger q, BigInteger[] x, BigInteger[] y)
    {
        if (x.length == 2)
        {
            // u^2 = -2
            return new BigInteger[]{ x[0].multiply(y[0]).subtract(x[1].multiply(y[1]).shiftLeft(1)).mod(q),
                x[0].multiply(y[1]).add(x[1].multiply(y[0])).mod(q) };
        }
        if (x.length == 4)
        {
            // v^2 = u
            BigInteger[] a = part(x, 0, 2), b = part(x, 2, 2), c = part(y, 0, 2), d = part(y, 2, 2);
            return join(towerAdd(q, towerMul(q, a, c), towerTimesU(q, towerMul(q, b, d))),
                towerAdd(q, towerMul(q, a, d), towerMul(q, b, c)));
        }
        // w^3 = v
        BigInteger[] x0 = part(x, 0, 4), x1 = part(x, 4, 4), x2 = part(x, 8, 4);
        BigInteger[] y0 = part(y, 0, 4), y1 = part(y, 4, 4), y2 = part(y, 8, 4);
        BigInteger[] z0 = towerAdd(q, towerMul(q, x0, y0), towerTimesV(q, towerAdd(q, towerMul(q, x1, y2),
            towerMul(q, x2, y1))));
        BigInteger[] z1 = towerAdd(q, towerAdd(q, towerMul(q, x0, y1), towerMul(q, x1, y0)),
            towerTimesV(q, towerMul(q, x2, y2)));
        BigInteger[] z2 = towerAdd(q, towerAdd(q, towerMul(q, x0, y2), towerMul(q, x1, y1)), towerMul(q, x2, y0));
        return join(join(z0, z1), z2);
    }

    private static BigInteger[] towerAdd(BigInteger q, BigInteger[] x, BigInteger[] y)
    {
        BigInteger[] z = new BigInteger[x.length];
        for (int k = 0; k != z.length; k++)
        {
            z[k] = x[k].add(y[k]).mod(q);
        }
        return z;
    }

    private static BigInteger[] towerSub(BigInteger q, BigInteger[] x, BigInteger[] y)
    {
        return towerAdd(q, x, towerScale(q, y, BigInteger.ONE.negate()));
    }

    private static boolean isZero(BigInteger[] x)
    {
        for (int k = 0; k != x.length; k++)
        {
            if (x[k].signum() != 0)
            {
                return false;
            }
        }
        return true;
    }

    // x y for x and y in F_q, as one coefficient, or in F_p2, as two
    private static BigInteger[] fieldMul(BigInteger q, BigInteger[] x, BigInteger[] y)
    {
        return x.length == 1 ? new BigInteger[]{ x[0].multiply(y[0]).mod(q) } : towerMul(q, x, y);
    }

    // x^-1 for x in F_p2, not 0: (a + b u)^-1 = (a - b u) / (a^2 + 2b^2)
    private static BigInteger[] towerInverse(BigInteger q, BigInteger[] x)
    {
        BigInteger norm = x[0].multiply(x[0]).add(x[1].multiply(x[1]).shiftLeft(1)).modInverse(q);
        return new BigInteger[]{ x[0].multiply(norm).mod(q), x[1].negate().multiply(norm).mod(q) };
    }

    // the Miller loop's doubling of T = (X, Y, Z) on y^2 = x^3 + b', b' = 5u, and its tangent: X3, Y3,
    // Z3 and the coefficients c0, cY and cX, elements of F_p2, one after another
    private static BigInteger[] millerDouble(BigInteger q, BigInteger[] x, BigInteger[] y, BigInteger[] z)
    {
        BigInteger[] uz2 = towerTimesU(q, towerMul(q, z, z)), y2 = towerMul(q, y, y);
        BigInteger[] nine = towerScale(q, uz2, BigInteger.valueOf(45));                    // 9b'Z^2
        BigInteger[] x3 = towerMul(q, towerScale(q, towerMul(q, x, y), BigInteger.valueOf(2)), towerSub(q, y2, nine));
        BigInteger[] y3 = towerSub(q, towerMul(q, towerAdd(q, y2, nine), towerAdd(q, y2, nine)),
            towerScale(q, towerMul(q, uz2, uz2), BigInteger.valueOf(2700)));             // 108 b'^2 Z^4
        BigInteger[] z3 = towerScale(q, towerMul(q, towerMul(q, y2, y), z), BigInteger.valueOf(8));
        BigInteger[] c0 = towerSub(q, y2, towerScale(q, uz2, BigInteger.valueOf(15)));     // Y^2 - 3b'Z^2
        BigInteger[] cy = towerScale(q, towerMul(q, y, z), BigInteger.valueOf(2));
        BigInteger[] cx = towerScale(q, towerMul(q, x, x), BigInteger.valueOf(3));
        return join(join(join(x3, y3), join(z3, c0)), join(cy, cx));
    }

    // the Miller loop's addition of (x2, y2) to T = (X, Y, Z), and the line through them: X3, Y3, Z3
    // and the coefficients c0, cY and cX, elements of F_p2, one after another
    private static BigInteger[] millerAdd(BigInteger q, BigInteger[] x, BigInteger[] y, BigInteger[] z,
        BigInteger[] x2, BigInteger[] y2)
    {
        BigInteger[] rr = towerSub(q, towerMul(q, y2, z), y), h = towerSub(q, towerMul(q, x2, z), x);
        BigInteger[] hh = towerMul(q, h, h), hhh = towerMul(q, hh, h), xhh = towerMul(q, x, hh);
        BigInteger[] aa = towerSub(q, towerSub(q, towerMul(q, towerMul(q, rr, rr), z), hhh),
            towerScale(q, xhh, BigInteger.valueOf(2)));
        BigInteger[] x3 = towerMul(q, h, aa);
        BigInteger[] y3 = towerSub(q, towerMul(q, rr, towerSub(q, xhh, aa)), towerMul(q, y, hhh));
        BigInteger[] z3 = towerMul(q, z, hhh);
        BigInteger[] c0 = towerSub(q, towerMul(q, rr, x2), towerMul(q, h, y2));
        return join(join(join(x3, y3), join(z3, c0)), join(h, rr));
    }

    // 2p for p = (X, Y, Z) in Jacobian coordinates over F_q or F_p2: X3, Y3 and Z3
    private static BigInteger[] jacobianDouble(BigInteger q, BigInteger[] x, BigInteger[] y, BigInteger[] z)
    {
        BigInteger[] xx = fieldMul(q, x, x), yy = fieldMul(q, y, y), xyy = fieldMul(q, x, yy);
        BigInteger[] x3 = towerSub(q, towerScale(q, fieldMul(q, xx, xx), BigInteger.valueOf(9)),
            towerScale(q, xyy, BigInteger.valueOf(8)));
        BigInteger[] y3 = towerSub(q, fieldMul(q, towerScale(q, xx, BigInteger.valueOf(3)),
            towerSub(q, towerScale(q, xyy, BigInteger.valueOf(4)), x3)), towerScale(q, fieldMul(q, yy, yy), BigInteger.valueOf(8)));
        BigInteger[] z3 = towerScale(q, fieldMul(q, y, z), BigInteger.valueOf(2));
        return join(join(x3, y3), z3);
    }

    // p + r for p = (X1, Y1, Z1) and r = (X2, Y2, Z2) in Jacobian coordinates over F_q or F_p2, their
    // coordinates each of the given number of coefficients, by the formulas whatever the points are:
    // X3, Y3 and Z3, and H and s after them
    private static BigInteger[] jacobianAdd(BigInteger q, BigInteger[] p, BigInteger[] r, int k)
    {
        BigInteger[] x1 = part(p, 0, k), y1 = part(p, k, k), z1 = part(p, 2 * k, k);
        BigInteger[] x2 = part(r, 0, k), y2 = part(r, k, k), z2 = part(r, 2 * k, k);
        BigInteger[] z1z1 = fieldMul(q, z1, z1), z2z2 = fieldMul(q, z2, z2);
        BigInteger[] u1 = fieldMul(q, x1, z2z2), s1 = fieldMul(q, fieldMul(q, y1, z2), z2z2);
        BigInteger[] h = towerSub(q, fieldMul(q, x2, z1z1), u1);
        BigInteger[] s = towerSub(q, fieldMul(q, fieldMul(q, y2, z1), z1z1), s1);
        BigInteger[] hh = fieldMul(q, h, h), hhh = fieldMul(q, hh, h), v = fieldMul(q, u1, hh);
        BigInteger[] x3 = towerSub(q, towerSub(q, fieldMul(q, s, s), hhh), towerScale(q, v, BigInteger.valueOf(2)));
        BigInteger[] y3 = towerSub(q, fieldMul(q, s, towerSub(q, v, x3)), fieldMul(q, s1, hhh));
        BigInteger[] z3 = fieldMul(q, fieldMul(q, z1, z2), h);
        return join(join(join(x3, y3), z3), join(h, s));
    }

    // Karabina's decompression, as Fp12.decompress takes it, of the compressed form g2, g3, g4, g5,
    // elements of F_p2: the twelve coefficients of g0 to g5
    private static BigInteger[] decompressed(BigInteger q, BigInteger[] c)
    {
        BigInteger[] g2 = part(c, 0, 2), g3 = part(c, 2, 2), g4 = part(c, 4, 2), g5 = part(c, 6, 2);
        BigInteger[] one = { BigInteger.ONE, BigInteger.ZERO }, num, den;
        if (!isZero(g2))
        {
            num = towerSub(q, towerAdd(q, towerTimesU(q, towerMul(q, g5, g5)),
                towerScale(q, towerMul(q, g4, g4), BigInteger.valueOf(3))), towerScale(q, g3, BigInteger.valueOf(2)));
            den = towerScale(q, g2, BigInteger.valueOf(4));
        }
        else
        {
            num = towerScale(q, towerMul(q, g4, g5), BigInteger.valueOf(2));
            den = isZero(g3) ? one : g3;
        }
        BigInteger[] g1 = towerMul(q, num, towerInverse(q, den));
        BigInteger[] b = towerSub(q, towerAdd(q, towerScale(q, towerMul(q, g1, g1), BigInteger.valueOf(2)),
            towerMul(q, g2, g5)), towerScale(q, towerMul(q, g3, g4), BigInteger.valueOf(3)));
        return join(join(towerAdd(q, towerTimesU(q, b), one), g1), c);
    }

    // x times s, for s in F_q
    private static BigInteger[] towerScale(BigInteger q, BigInteger[] x, BigInteger s)
    {
        BigInteger[] z = new BigInteger[x.length];
        for (int k = 0; k != z.length; k++)
        {
            z[k] = x[k].multiply(s).mod(q);
        }
        return z;
    }

    // x u for x in F_p2: (x0 + x1 u) u = -2 x1 + x0 u
    private static BigInteger[] towerTimesU(BigInteger q, BigInteger[] x)
    {
        return new BigInteger[]{ x[1].shiftLeft(1).negate().mod(q), x[0] };
    }

    // x v for x in F_p4: (a + b v) v = b u + a v
    private static BigInteger[] towerTimesV(BigInteger q, BigInteger[] x)
    {
        return join(towerTimesU(q, part(x, 2, 2)), part(x, 0, 2));
    }

    // conj(x) = a - b v for x = a + b v in F_p4
    private static BigInteger[] towerConjugate(BigInteger q, BigInteger[] x)
    {
        return join(part(x, 0, 2), towerScale(q, part(x, 2, 2), BigInteger.ONE.negate()));
    }

    // Granger and Scott's formula, as Fp12.cyclotomicSqr takes it for m y:
    // (3a^2 - 2m conj(a)) + (3c^2 v + 2m conj(b)) w + (3b^2 - 2m conj(c)) w^2
    private static BigInteger[] cyclotomicSquare(BigInteger q, BigInteger[] x, BigInteger m)
    {
        BigInteger three = BigInteger.valueOf(3), minusTwo = BigInteger.valueOf(-2);
        BigInteger[] a = part(x, 0, 4), b = part(x, 4, 4), c = part(x, 8, 4);
        BigInteger[] z0 = towerAdd(q, towerScale(q, towerMul(q, a, a), three),
            towerScale(q, towerConjugate(q, a), m.multiply(minusTwo)));
        BigInteger[] z1 = towerAdd(q, towerScale(q, towerTimesV(q, towerMul(q, c, c)), three),
            towerScale(q, towerConjugate(q, b), m.shiftLeft(1)));
        BigInteger[] z2 = towerAdd(q, towerScale(q, towerMul(q, b, b), three),
            towerScale(q, towerConjugate(q, c), m.multiply(minusTwo)));
        return join(join(z0, z1), z2);
    }

    // Karabina's formulas, as Fp12.compressedSqr takes them, for g2, g3, g4 and g5 in F_p2:
    // h2 = 2(g2 + 3u B45), h3 = 3(A45 - (u + 1) B45) - 2g3, h4 = 3(A23 - (u + 1) B23) - 2g4 and
    // h5 = 2(g5 + 3B23), for A_ij = (g_i + g_j)(g_i + u g_j) and B_ij = g_i g_j
    private static BigInteger[] compressedSquare(BigInteger q, BigInteger[] c)
    {
        BigInteger[] g2 = part(c, 0, 2), g3 = part(c, 2, 2), g4 = part(c, 4, 2), g5 = part(c, 6, 2);
        BigInteger three = BigInteger.valueOf(3), two = BigInteger.valueOf(2), minusTwo = BigInteger.valueOf(-2);
        BigInteger[] b45 = towerMul(q, g4, g5), b23 = towerMul(q, g2, g3);
        BigInteger[] a45 = towerMul(q, towerAdd(q, g4, g5), towerAdd(q, g4, towerTimesU(q, g5)));
        BigInteger[] a23 = towerMul(q, towerAdd(q, g2, g3), towerAdd(q, g2, towerTimesU(q, g3)));
        BigInteger[] h2 = towerScale(q, towerAdd(q, g2, towerScale(q, towerTimesU(q, b45), three)), two);
        BigInteger[] h3 = towerAdd(q, towerScale(q, towerAdd(q, a45,
            towerScale(q, towerAdd(q, b45, towerTimesU(q, b45)), BigInteger.ONE.negate())), three),
            towerScale(q, g3, minusTwo));
        BigInteger[] h4 = towerAdd(q, towerScale(q, towerAdd(q, a23,
            towerScale(q, towerAdd(q, b23, towerTimesU(q, b23)), BigInteger.ONE.negate())), three),
            towerScale(q, g4, minusTwo));
        BigInteger[] h5 = towerScale(q, towerAdd(q, g5, towerScale(q, b23, three)), two);
        return join(join(h2, h3), join(h4, h5));
    }

    private static BigInteger[] part(BigInteger[] x, int off, int len)
    {
        BigInteger[] z = new BigInteger[len];
        System.arraycopy(x, off, z, 0, len);
        return z;
    }

    private static BigInteger[] join(BigInteger[] x, BigInteger[] y)
    {
        BigInteger[] z = new BigInteger[x.length + y.length];
        System.arraycopy(x, 0, z, 0, x.length);
        System.arraycopy(y, 0, z, x.length, y.length);
        return z;
    }

    /**
     * SM9Curve.multiplySecure, the comb, for P1 and a signing key: held to the default multiplier on
     * recipient points and random points, over the edges of the range - 0, 1, 2, N - 10, N - 2, N - 1, N,
     * the top bit alone and 2^256 - 1 - and random scalars, and to keeping its own table with the point,
     * not FixedPointUtil's: the points are the same whichever multiplier runs, so only the table shows
     * which one did.
     */
    private void checkG1SecretMultiply()
        throws Exception
    {
        String combName = (String)staticField(Class.forName("org.bouncycastle.math.ec.sm9.SM9G1Multiplier"), "PRECOMP_NAME");
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N;
        SM9EncMasterPublicKeyParameters master = new SM9EncMasterPrivateKeyParameters(
            BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).getPublicKeyParameters();
        BigInteger[] edges = { BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), n.subtract(BigInteger.valueOf(10)),
            n.subtract(BigInteger.valueOf(2)), n.subtract(BigInteger.ONE), n, BigInteger.ONE.shiftLeft(255),
            BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE) };
        for (int p = 0; p != 4; p++)
        {
            ECPoint q = (p < 2)
                ? master.recipientPoint(Strings.toByteArray("Bob" + p))
                : SM9Curve.P1.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).normalize();
            ECPoint comb = copyG1(q);
            for (int i = 0; i != edges.length + 16; i++)
            {
                BigInteger k = (i < edges.length) ? edges[i] : BigIntegers.createRandomBigInteger(256, random);
                isTrue("multiplySecure gives [" + k.toString(16) + "]Q", SM9Curve.multiplySecure(comb, k).equals(q.multiply(k)));
            }
            isTrue("multiplySecure keeps its table with its point",
                SM9Curve.G1.getPreCompInfo(comb, combName) != null
                    && SM9Curve.G1.getPreCompInfo(comb, FixedPointUtil.PRECOMP_NAME) == null);
            isTrue("the default multiplier keeps its table with its point",
                SM9Curve.G1.getPreCompInfo(q, WNafUtil.PRECOMP_NAME) != null);
        }
    }

    /**
     * multiplySecure's comb runs over a table of thirty-two multiples of its point and their doubles, which
     * the point keeps: the table is held to being made with one draw, for the random representative it is
     * made from, and kept, and to holding the same points for another instance of the point; its entries, the
     * comb and its lookups through checkComb; and each call to drawing its blinding, its factor, the entries
     * its lookups start at and its inversion's factor.
     */
    private void checkG1FixedBaseMultiply()
        throws Exception
    {
        Class multiplier = Class.forName("org.bouncycastle.math.ec.sm9.SM9G1Multiplier");
        java.lang.reflect.Method combTable = declaredMethod(multiplier, "combTable", new Class[]{ ECPoint.class });
        java.lang.reflect.Method comb = declaredMethod(multiplier, "comb",
            new Class[]{ ECCurve.class, int[].class, int[].class });
        java.lang.reflect.Method lookup = declaredMethod(multiplier, "lookup",
            new Class[]{ int[].class, int.class, int.class, int.class, int.class, int[].class });
        String name = (String)staticField(multiplier, "PRECOMP_NAME");
        ECPoint p1 = copyG1(SM9Curve.P1);

        // the table P1 keeps, and one made for another instance of P1: made with one draw of 32 bytes, for the
        // random representative, and kept
        int[] table = (int[])combTable.invoke(null, new Object[]{ SM9Curve.P1 });
        isTrue("P1 keeps a table of 32 points and their doubles",
            table.length == 32 * 32 && SM9Curve.G1.getPreCompInfo(SM9Curve.P1, name) != null);
        ECPoint fresh = copyG1(SM9Curve.P1);
        RecordingSource recording = new RecordingSource(null);
        int[] made = (int[])withSource(recording, combTable, null, new Object[]{ fresh });
        isTrue("the comb's table is made with the draw of its random representative: " + recording.lengths(),
            "32".equals(recording.lengths()));
        isTrue("the table is kept", combTable.invoke(null, new Object[]{ fresh }) == made);
        isTrue("the table holds the same points for another instance of the point", Arrays.areEqual(made, table));
        checkComb(comb, SM9Curve.G1, table, p1, lookup);

        // each call draws its blinding, 8 bytes, the factor its entries are carried by, an element of F_q of
        // 32, one byte for each of the sixty-four lookups and the inversion's factor, 32
        recording.clear();
        try
        {
            CryptoServicesRegistrar.setSecureRandom(recording);
            SM9Curve.multiplySecure(SM9Curve.P1, BigInteger.valueOf(12345));
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        isTrue("the G1 comb draws its blinding, its factor, the entries its lookups start at and the inversion's factor: "
            + recording.lengths(), "8 32 64 32".equals(recording.lengths()));
    }

    // the i-th of a table's affine points of G1, each x || y in sixteen limbs as Fp holds an element, as
    // the point it holds: in the comb's table, entry d is the (2d)th and its double the (2d + 1)th
    private static ECPoint g1TablePoint(int[] table, int i)
    {
        return SM9Curve.G1.createPoint(fqValue(Arrays.copyOfRange(table, i * 16, i * 16 + 8)),
            fqValue(Arrays.copyOfRange(table, i * 16 + 8, i * 16 + 16)));
    }

    /**
     * sumOfTwoMultipliesSecure, [a]P + [b]Q by one comb over both points' tables: held to the default
     * multiplier over P1 and a master public key, two random points, a point and itself, a point and another
     * instance of it and a point and its negation, over every pair of the edges of the range and random pairs,
     * and to keeping each point's table with it; the comb, through reflection, over the tables of a point and
     * of itself, where an addition meets the entry it adds and takes its double from the table, and of a point
     * and of its negation, whose sum is infinity; its reads of the second table through lookup; and its draws.
     */
    private void checkG1SumOfTwoMultiplies()
        throws Exception
    {
        Class multiplier = Class.forName("org.bouncycastle.math.ec.sm9.SM9G1Multiplier");
        java.lang.reflect.Method combTable = declaredMethod(multiplier, "combTable", new Class[]{ ECPoint.class });
        java.lang.reflect.Method comb = declaredMethod(multiplier, "comb",
            new Class[]{ ECCurve.class, int[][].class, int[][].class });
        String combName = (String)staticField(multiplier, "PRECOMP_NAME");

        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N;
        SM9EncMasterPublicKeyParameters master = new SM9EncMasterPrivateKeyParameters(
            BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).getPublicKeyParameters();
        ECPoint ppub = SM9Curve.g1FromUncompressed(master.getEncoded());
        ECPoint u = SM9Curve.P1.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).normalize();
        ECPoint v = SM9Curve.P1.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).normalize();
        ECPoint negated = u.negate().normalize();
        ECPoint[][] pairs = { { SM9Curve.P1, ppub }, { u, v }, { u, u }, { u, copyG1(u) }, { u, negated } };
        BigInteger[] edges = { BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), n.subtract(BigInteger.valueOf(2)),
            n.subtract(BigInteger.ONE), n, BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE) };
        for (int p = 0; p != pairs.length; p++)
        {
            ECPoint a = pairs[p][0], b = pairs[p][1];
            // the default multiplier's multiples of the two points by the edges, each formed once
            ECPoint[] aTimes = new ECPoint[edges.length], bTimes = new ECPoint[edges.length];
            for (int e = 0; e != edges.length; e++)
            {
                aTimes[e] = a.multiply(edges[e]);
                bTimes[e] = b.multiply(edges[e]);
            }
            for (int i = 0; i != edges.length * edges.length + 8; i++)
            {
                boolean edge = i < edges.length * edges.length;
                BigInteger ka = edge ? edges[i / edges.length] : BigIntegers.createRandomBigInteger(256, random);
                BigInteger kb = edge ? edges[i % edges.length] : BigIntegers.createRandomBigInteger(256, random);
                isTrue("sumOfTwoMultipliesSecure gives [" + ka.toString(16) + "]P + [" + kb.toString(16) + "]Q, pair " + p,
                    SM9Curve.sumOfTwoMultipliesSecure(a, ka, b, kb).equals(edge
                        ? aTimes[i / edges.length].add(bTimes[i % edges.length]) : a.multiply(ka).add(b.multiply(kb))));
            }
            isTrue("sumOfTwoMultipliesSecure keeps each point's table with the point, pair " + p,
                SM9Curve.G1.getPreCompInfo(a, combName) != null && SM9Curve.G1.getPreCompInfo(b, combName) != null);
        }

        // the comb over the tables of u and of u, and of u and of -u, over blinded scalars of the same value
        // for both, as the call would pass them, less 2^64 - 1: all columns 0, all 31, the top bit alone, random
        int[] tu = (int[])combTable.invoke(null, new Object[]{ u });
        int[] tn = (int[])combTable.invoke(null, new Object[]{ negated });
        int[] undoubled = Arrays.clone(tu);
        for (int d = 0; d != 32; d++)
        {
            System.arraycopy(tu, d * 32, undoubled, d * 32 + 16, 16);
        }
        BigInteger offset = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        BigInteger[] ks = { BigInteger.ZERO, BigInteger.ONE.shiftLeft(320).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(319), new BigInteger(320, random) };
        for (int i = 0; i != ks.length; i++)
        {
            int[] k = Nat.fromBigInteger(320, ks[i]);
            ECPoint twice = u.multiply(ks[i].add(offset).shiftLeft(1).mod(n));
            isTrue("the comb over a point and itself, blinded scalar " + i, comb.invoke(null,
                new Object[]{ SM9Curve.G1, new int[][]{ tu, tu }, new int[][]{ k, k } }).equals(twice));
            isTrue("the comb over a point and itself takes the double the table holds, blinded scalar " + i,
                !comb.invoke(null, new Object[]{ SM9Curve.G1, new int[][]{ undoubled, undoubled },
                    new int[][]{ k, k } }).equals(twice));
            isTrue("the comb over a point and its negation, blinded scalar " + i, ((ECPoint)comb.invoke(null,
                new Object[]{ SM9Curve.G1, new int[][]{ tu, tn }, new int[][]{ k, k } })).isInfinity());
        }

        // the second table is read through lookup: a short one is read past its end, although the entry
        // picked is its first
        checkReadsPastEnd("the G1 comb read the entry it picks from its second table alone",
            "the G1 comb reads every entry of its second table through lookup", comb, null, new Object[]{ SM9Curve.G1,
            new int[][]{ tu, Arrays.copyOfRange(tu, 0, 31 * 32) }, new int[][]{ new int[10], new int[10] } }, multiplier);

        // each call draws a blinding for each scalar, 8 bytes each, the factor both tables are carried by, 32,
        // one byte for each of the 128 lookups and the inversion's factor, 32, the tables being made before
        RecordingSource recording = new RecordingSource(null);
        try
        {
            CryptoServicesRegistrar.setSecureRandom(recording);
            SM9Curve.sumOfTwoMultipliesSecure(SM9Curve.P1, BigInteger.valueOf(12345), ppub, BigInteger.valueOf(678));
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        isTrue("the comb over two tables draws its blindings, its factor, the entries its lookups start at and "
            + "the inversion's factor: " + recording.lengths(), "8 8 32 128 32".equals(recording.lengths()));
    }

    /**
     * SM9Curve.multiplyPublic, verification's [h1]S, runs the GLV method over G1's endomorphism
     * (x, y) -&gt; (beta x, y), the multiplication by lambda, a cube root of 1 mod N: beta and lambda are held
     * to their expressions in t, the endomorphism to the multiplication by lambda and its split of k to
     * k1 + k2 lambda, with k1 and k2 within 128 bits, which no product shows; the multiplication to the default
     * multiplier on P1, recipient and random points over the ends of the range, lambda and its square, and
     * random scalars, and to keeping the endomorphism's image of its point, which the default one does not make.
     */
    private void checkG1PublicMultiply()
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N, q = SM9Curve.G1.getField().getCharacteristic();
        BigInteger t = (BigInteger)staticField(SM9Curve.class, "T"), t2 = t.multiply(t), t3 = t2.multiply(t);
        BigInteger beta = t3.multiply(BigInteger.valueOf(18)).add(t2.multiply(BigInteger.valueOf(18)))
            .add(t.multiply(BigInteger.valueOf(9))).add(BigInteger.valueOf(2)).negate().mod(q);
        BigInteger lambda = t3.multiply(BigInteger.valueOf(36)).add(t2.multiply(BigInteger.valueOf(18)))
            .add(t.multiply(BigInteger.valueOf(6))).add(BigInteger.valueOf(2)).negate().mod(n);
        isTrue("beta is a cube root of 1 other than 1",
            beta.modPow(BigInteger.valueOf(3), q).equals(BigInteger.ONE) && !beta.equals(BigInteger.ONE));
        isTrue("lambda is a cube root of 1 other than 1",
            lambda.multiply(lambda).add(lambda).add(BigInteger.ONE).mod(n).signum() == 0 && !lambda.equals(BigInteger.ONE));

        GLVEndomorphism endomorphism = (GLVEndomorphism)staticField(SM9Curve.class, "G1_ENDOMORPHISM");
        // the multiplication reads beta, through the point map, and the split; lambda is carried for other readers
        GLVTypeBParameters carried = (GLVTypeBParameters)declaredField(GLVTypeBEndomorphism.class, "parameters")
            .get(endomorphism);
        isTrue("the endomorphism carries beta and lambda", carried.getBeta().equals(beta) && carried.getLambda().equals(lambda));
        BigInteger[] edges = { BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), lambda, lambda.multiply(lambda).mod(n),
            n.subtract(lambda), n.subtract(BigInteger.valueOf(2)), n.subtract(BigInteger.ONE), n, n.add(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(127), BigInteger.ONE.shiftLeft(128), BigInteger.ONE.shiftLeft(255),
            BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE) };
        for (int i = 0; i != edges.length + 1000; i++)
        {
            BigInteger k = ((i < edges.length) ? edges[i] : BigIntegers.createRandomBigInteger(256, random)).mod(n);
            BigInteger[] split = endomorphism.decomposeScalar(k);
            isTrue("the split of " + k.toString(16) + " is k1 + k2 lambda",
                split[0].add(split[1].multiply(lambda)).subtract(k).mod(n).signum() == 0);
            isTrue("the split of " + k.toString(16) + " is within 128 bits",
                split[0].bitLength() <= 128 && split[1].bitLength() <= 128);
        }

        SM9EncMasterPublicKeyParameters master = new SM9EncMasterPrivateKeyParameters(
            BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).getPublicKeyParameters();
        for (int p = 0; p != 5; p++)
        {
            ECPoint point = (p == 0) ? SM9Curve.P1
                : (p < 3) ? master.recipientPoint(Strings.toByteArray("Bob" + p))
                : SM9Curve.P1.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random)).normalize();
            ECPoint glv = copyG1(point), plain = copyG1(point);
            ECPoint image = SM9Curve.G1.createPoint(point.getAffineXCoord().toBigInteger().multiply(beta).mod(q),
                point.getAffineYCoord().toBigInteger());
            isTrue("the endomorphism is the multiplication by lambda, point " + p,
                copyG1(point).multiply(lambda).equals(image) && endomorphism.getPointMap().map(copyG1(point)).equals(image));
            for (int i = 0; i != edges.length + 24; i++)
            {
                BigInteger k = (i < edges.length) ? edges[i] : BigIntegers.createRandomBigInteger(8 + 31 * (i % 9), random);
                isTrue("multiplyPublic gives [" + k.toString(16) + "]P, point " + p,
                    SM9Curve.multiplyPublic(glv, k).equals(plain.multiply(k)));
            }
            isTrue("multiplyPublic keeps the endomorphism's image with its point, point " + p,
                SM9Curve.G1.getPreCompInfo(glv, EndoUtil.PRECOMP_NAME) != null);
            isTrue("the default multiplier makes no image of its point, point " + p,
                SM9Curve.G1.getPreCompInfo(plain, EndoUtil.PRECOMP_NAME) == null);
        }
    }

    /**
     * multiplySecure and sumOfTwoMultipliesSecure refuse a result that is not on the curve: their comb forms
     * it with createPoint, which does not check, so a fault in the table a point keeps - here the lowest bit
     * of every entry's x flipped - is caught only by that check. The points are made for the check, so that
     * the faulted table stays with them.
     */
    private void checkG1ResultIsChecked()
        throws Exception
    {
        java.lang.reflect.Method combTable = declaredMethod(Class.forName("org.bouncycastle.math.ec.sm9.SM9G1Multiplier"),
            "combTable", new Class[]{ ECPoint.class });

        BigInteger k = new BigInteger("5C4E1F3A9B0D2E7F8A6B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F", 16);
        ECPoint p = copyG1(SM9Curve.P1.multiply(BigInteger.valueOf(7)).normalize());
        ECPoint q = copyG1(SM9Curve.P1.multiply(BigInteger.valueOf(11)).normalize());
        isTrue("multiplySecure before the fault", SM9Curve.multiplySecure(p, k).equals(p.multiply(k)));
        isTrue("sumOfTwoMultipliesSecure before the fault",
            SM9Curve.sumOfTwoMultipliesSecure(q, k, p, k).equals(q.add(p).multiply(k)));

        int[] table = (int[])combTable.invoke(null, new Object[]{ p });
        for (int e = 0; e != 32; e++)
        {
            table[32 * e] ^= 1;
        }
        try
        {
            SM9Curve.multiplySecure(p, k);
            fail("multiplySecure returned the product of a faulted table");
        }
        catch (IllegalStateException e)
        {
            isTrue("multiplySecure's refusal: " + e.getMessage(), "Invalid result".equals(e.getMessage()));
        }
        try
        {
            SM9Curve.sumOfTwoMultipliesSecure(q, k, p, k);
            fail("sumOfTwoMultipliesSecure returned the sum over a faulted table");
        }
        catch (IllegalStateException e)
        {
            isTrue("sumOfTwoMultipliesSecure's refusal: " + e.getMessage(), "Invalid result".equals(e.getMessage()));
        }
    }

    // a copy of an affine G1 point, which carries none of the precomputation made for the original
    private static ECPoint copyG1(ECPoint p)
    {
        return SM9Curve.G1.createPoint(p.getAffineXCoord().toBigInteger(), p.getAffineYCoord().toBigInteger());
    }

    /**
     * powSecure splits the exponent into four through the Frobenius, blinds the split, reads the four
     * exponents in sign-aligned columns from a table of sixteen, and carries each running value as m y for a
     * random non-zero m of F_q, squaring it by the cyclotomic squaring rewritten for that form. None of that
     * shows in a result, so the pieces are held directly, through reflection: the rewritten squaring against
     * the general product, the exponentiation against pow, the split's basis, rounding constants, offsets and
     * exponents, the recoding, the table, the columns and their reads through lookup, and the draws powSecure
     * and the tower's inversion make. And SM9Curve.blind, through which the combs blind their secrets, is held
     * to giving 320 bits that stand for the scalar mod N, and, at the ends of the range of the multiplier it
     * draws, to its exact value.
     */
    private void checkSecretExponentiation()
        throws Exception
    {
        // the eight limbs of m, an element of F_q in the Montgomery form Fp holds it in, followed by zeros stand
        // for m as an element of F_p12, whose product with y is m y
        java.lang.reflect.Method toLimbs = declaredMethod(Class.forName("org.bouncycastle.math.ec.sm9.Fp"),
            "fromBigInteger", new Class[]{ BigInteger.class, int[].class, int.class });
        java.lang.reflect.Constructor fromLimbs = declaredConstructor(Fp12.class, new Class[]{ int[].class });
        java.lang.reflect.Field limbs = declaredField(Fp12.class, "limbs");
        java.lang.reflect.Method square = declaredMethod(Fp12.class, "cyclotomicSqr", new Class[]{ int[].class,
            int.class, int[].class, int.class, int[].class, int.class, int[].class, int.class });
        int squareScratch = ((Integer)staticField(Fp12.class, "CYCLOTOMIC_SQR_SCRATCH")).intValue();
        java.lang.reflect.Method blind = declaredMethod(SM9Curve.class, "blind", new Class[]{ BigInteger.class });
        java.lang.reflect.Method decompose = declaredMethod(Fp12.class, "decompose", new Class[]{ BigInteger.class });
        java.lang.reflect.Method recode = declaredMethod(Fp12.class, "recode", new Class[]{ int[][].class });
        java.lang.reflect.Method splitTable = declaredMethod(Fp12.class, "splitTable", new Class[]{ int[].class });
        java.lang.reflect.Method splitPower = declaredMethod(Fp12.class, "splitPower",
            new Class[]{ int[].class, int[].class, int[][].class });

        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N;
        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        Fp12 g = SM9Pairing.pairing(SM9Curve.P1, SM9Curve.P2);

        BigInteger[] masks = { BigInteger.ONE, q.subtract(BigInteger.ONE),
            BigIntegers.createRandomInRange(BigInteger.valueOf(2), q.subtract(BigInteger.valueOf(2)), random) };
        for (int i = 0; i != masks.length; i++)
        {
            Fp12 y = g.pow(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
            int[] m = new int[8];
            toLimbs.invoke(null, new Object[]{ masks[i], m, Integers.valueOf(0) });
            Fp12 my = y.multiply((Fp12)fromLimbs.newInstance(new Object[]{ Arrays.copyOf(m, 96) }));
            int[] z = new int[96];
            square.invoke(null, new Object[]{ limbs.get(my), Integers.valueOf(0), m, Integers.valueOf(0), z,
                Integers.valueOf(0), new int[squareScratch], Integers.valueOf(0) });
            isTrue("the masked squaring gives the square of m y", Arrays.areEqual(z, (int[])limbs.get(my.multiply(my))));
        }

        for (int i = 0; i != 8; i++)
        {
            Fp12 h = g.pow(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
            BigInteger e = new BigInteger(256 - 32 * i, random).mod(n);
            isTrue("powSecure agrees with pow over a random base at bit length " + e.bitLength(),
                h.powSecure(e).equals(h.pow(e)));
        }

        // the basis: coordinate j of row i is x t + y for {x, y} = SPLIT_BASIS[i][j]; each row stands for 0 mod
        // N, raising to q being raising to lambda = q mod N on the order-N subgroup, and the determinant, -N,
        // the index in Z^4 of the lattice of the vectors that do, makes the rows span that lattice
        BigInteger t = (BigInteger)staticField(SM9Curve.class, "T");
        BigInteger lambda = q.mod(n);
        isTrue("q is 6t^2 mod N", lambda.equals(t.multiply(t).multiply(BigInteger.valueOf(6))));
        int[][][] rows = (int[][][])staticField(Fp12.class, "SPLIT_BASIS");
        BigInteger[][] b = new BigInteger[4][4];
        for (int i = 0; i != 4; i++)
        {
            BigInteger sum = BigInteger.ZERO;
            for (int j = 0; j != 4; j++)
            {
                b[i][j] = t.multiply(BigInteger.valueOf(rows[i][j][0])).add(BigInteger.valueOf(rows[i][j][1]));
                sum = sum.add(b[i][j].multiply(lambda.pow(j)));
            }
            isTrue("row " + i + " of the split's basis stands for 0", sum.mod(n).signum() == 0);
        }
        isTrue("the split's basis has determinant -N", determinant(b).equals(n.negate()));

        // (1, 0, 0, 0) = sum_i (a_i / N) b_i for a0 = 6t^3 + 6t^2 + 2t, a1 = 6t^3 - t, a2 = 2t + 1 and
        // a3 = 6t^3 + 6t^2 + t, and the rounding constants are round(2^320 a_i / N)
        BigInteger t2 = t.multiply(t), t3 = t2.multiply(t), six = BigInteger.valueOf(6), two = BigInteger.valueOf(2);
        BigInteger[] a = { six.multiply(t3.add(t2)).add(two.multiply(t)), six.multiply(t3).subtract(t),
            two.multiply(t).add(BigInteger.ONE), six.multiply(t3.add(t2)).add(t) };
        int[][] rounding = (int[][])staticField(Fp12.class, "SPLIT_ROUNDING");
        for (int j = 0; j != 4; j++)
        {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 0; i != 4; i++)
            {
                sum = sum.add(a[i].multiply(b[i][j]));
            }
            isTrue("column " + j + " of sum_i a_i b_i", sum.equals(j == 0 ? n : BigInteger.ZERO));
        }
        BigInteger[] roundingValues = new BigInteger[4];
        for (int i = 0; i != 4; i++)
        {
            roundingValues[i] = Nat.toBigInteger(8, rounding[i]);
            isTrue("rounding constant " + i, roundingValues[i].equals(
                a[i].shiftLeft(320).add(n.shiftRight(1)).divide(n)));
        }

        // (e, 0, 0, 0) - sum_i c_i b_i, c_i within 1/2 + 2^-65 of e a_i / N, has coordinate j no larger
        // than (1/2 + 2^-65) sum_i |b_ij|; to that the draw adds sum_i (offset_i + r_i) b_i for r_i
        // from 0 to 2^16 - 1, so, scaled by 2^66, coordinate j lies between
        // 2^66 (sum_i offset_i b_ij + (2^16 - 1) sum_i min(b_ij, 0)) - (2^65 + 2) sum_i |b_ij| and
        // 2^66 (sum_i offset_i b_ij + (2^16 - 1) sum_i max(b_ij, 0)) + (2^65 + 2) sum_i |b_ij|: which
        // are to be non-negative and below 2^82 for k0 and 2^81 for the others
        int[] offsets = (int[])staticField(Fp12.class, "SPLIT_OFFSETS");
        for (int j = 0; j != 4; j++)
        {
            BigInteger w = BigInteger.ZERO, low = BigInteger.ZERO, high = BigInteger.ZERO, size = BigInteger.ZERO;
            for (int i = 0; i != 4; i++)
            {
                w = w.add(b[i][j].multiply(BigInteger.valueOf(offsets[i])));
                BigInteger spread = b[i][j].multiply(BigInteger.valueOf(0xFFFF));
                if (b[i][j].signum() < 0)
                {
                    low = low.add(spread);
                }
                else
                {
                    high = high.add(spread);
                }
                size = size.add(b[i][j].abs());
            }
            BigInteger error = size.multiply(BigInteger.ONE.shiftLeft(65).add(two));
            isTrue("coordinate " + j + " of the split is non-negative",
                w.add(low).shiftLeft(66).subtract(error).signum() >= 0);
            isTrue("coordinate " + j + " of the split is in range",
                w.add(high).shiftLeft(66).add(error).compareTo(BigInteger.ONE.shiftLeft(66 + (j == 0 ? 82 : 81))) < 0);
        }

        // the exponents it forms, worked out on BigInteger, at the ends of the range of the draw - each r_i 0
        // or 2^16 - 1, r_0 without its lowest bit, which is set where k0 would be even - for exponents at the
        // ends of their own range, in between and at random
        BigInteger[] exponents = { BigInteger.ZERO, BigInteger.ONE, n.shiftRight(1), n.subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(255), BigIntegers.createRandomInRange(BigInteger.ZERO, n.subtract(BigInteger.ONE), random) };
        byte[][] ends = { new byte[8], Hex.decode("ffffffffffffffff"), Hex.decode("0000ffff0000ffff"),
            Hex.decode("ffff0000ffff0000") };
        for (int i = 0; i != exponents.length; i++)
        {
            for (int d = 0; d != ends.length; d++)
            {
                int[][] k = (int[][])withSource(new FixedSecureRandom(ends[d]), decompose, null, new Object[]{ exponents[i] });
                BigInteger[] want = new BigInteger[4];
                for (int j = 0; j != 4; j++)
                {
                    want[j] = j == 0 ? exponents[i] : BigInteger.ZERO;
                }
                for (int r = 0; r != 4; r++)
                {
                    BigInteger c = exponents[i].multiply(roundingValues[r]).add(BigInteger.ONE.shiftLeft(319)).shiftRight(320);
                    int drawn = ((ends[d][2 * r] & 0xFF) << 8) | (ends[d][2 * r + 1] & 0xFF);
                    c = c.subtract(BigInteger.valueOf(offsets[r] + (r == 0 ? drawn & 0xFFFE : drawn)));
                    for (int j = 0; j != 4; j++)
                    {
                        want[j] = want[j].subtract(c.multiply(b[r][j]));
                    }
                }
                if (!want[0].testBit(0))
                {
                    for (int j = 0; j != 4; j++)
                    {
                        want[j] = want[j].add(b[0][j]);
                    }
                }
                for (int j = 0; j != 4; j++)
                {
                    isTrue("the split of " + exponents[i].toString(16) + " at the end of its draw " + d,
                        Nat.toBigInteger(3, k[j]).equals(want[j]));
                }
                checkSplit(k, exponents[i], lambda);
            }
        }
        for (int i = 0; i != 64; i++)
        {
            BigInteger e = BigIntegers.createRandomInRange(BigInteger.ZERO, n.subtract(BigInteger.ONE), random);
            checkSplit((int[][])decompose.invoke(null, new Object[]{ e }), e, lambda);
        }

        // the recoding: the digits of k0 are 1 in the top column and, below it, -1 where bit c of S is set and
        // 1 elsewhere; those of k_j are k0's where bit c of D_j is set and 0 elsewhere; each adds up to its
        // exponent: over random splits, and over k0 of 1, all of whose digits below the top are -1, and
        // 2^82 - 1, all of whose are 1, with k_j 0 or as large as the recoding takes
        int[][][] splits = new int[66][][];
        for (int i = 0; i != 64; i++)
        {
            splits[i] = (int[][])decompose.invoke(null, new Object[]{
                BigIntegers.createRandomInRange(BigInteger.ZERO, n.subtract(BigInteger.ONE), random) });
        }
        splits[64] = new int[][]{ { 1, 0, 0 }, { 0, 0, 0 }, { 0, 0, 1 << 17 }, { 1, 0, 0 } };
        splits[65] = new int[][]{ { -1, -1, (1 << 18) - 1 }, { -1, -1, (1 << 18) - 1 }, { 0, 0, 0 }, { 5, 0, 0 } };
        for (int i = 0; i != splits.length; i++)
        {
            int[][] digits = new int[4][];
            for (int j = 0; j != 4; j++)
            {
                digits[j] = Arrays.clone(splits[i][j]);
            }
            recode.invoke(null, new Object[]{ digits });
            BigInteger s = Nat.toBigInteger(3, digits[0]);
            isTrue("the recoding marks no column at or above the top", s.bitLength() <= 81);
            for (int j = 0; j != 4; j++)
            {
                BigInteger dj = Nat.toBigInteger(3, digits[j]), sum = BigInteger.ZERO;
                isTrue("the recoding's digits lie in the columns", dj.bitLength() <= 82);
                for (int c = 81; c >= 0; c--)
                {
                    BigInteger digit = j == 0 || dj.testBit(c) ? (s.testBit(c) ? BigInteger.ONE.negate() : BigInteger.ONE)
                        : BigInteger.ZERO;
                    sum = sum.shiftLeft(1).add(digit);
                }
                isTrue("the digits of exponent " + j + " of split " + i + " add up to it",
                    sum.equals(Nat.toBigInteger(3, splits[i][j])));
            }
        }

        // the table: entry v + 8s is m (g g^(q v1) g^(q^2 v2) g^(q^3 v3))^(1 - 2s), none of whose
        // coefficients is 0, as a random element of G_T has none, whatever m is
        Fp12 h = g.pow(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
        Fp12[] powers = new Fp12[16];
        for (int u = 0; u != 16; u++)
        {
            BigInteger x = BigInteger.ONE;
            for (int j = 1; j != 4; j++)
            {
                if (((u >>> (j - 1)) & 1) != 0)
                {
                    x = x.add(lambda.pow(j));
                }
            }
            powers[u] = h.pow(u < 8 ? x.mod(n) : x.negate().mod(n));
        }
        int[] m = new int[8];
        int[] table = null;
        for (int i = 0; i != masks.length; i++)
        {
            toLimbs.invoke(null, new Object[]{ masks[i], m, Integers.valueOf(0) });
            Fp12 mm = (Fp12)fromLimbs.newInstance(new Object[]{ Arrays.copyOf(m, 96) });
            table = (int[])splitTable.invoke(h, new Object[]{ m });
            isTrue("powSecure's table has 16 entries", table.length == 16 * 96);
            for (int u = 0; u != 16; u++)
            {
                isTrue("powSecure's table entry " + u, Arrays.areEqual(Arrays.copyOfRange(table, u * 96, (u + 1) * 96),
                    (int[])limbs.get(powers[u].multiply(mm))));
                checkNoZeroElement("powSecure's table entry " + u + " has no coefficient 0", table, u * 96, 96);
            }
        }

        // the columns give h^(k0 + k1 q + k2 q^2 + k3 q^3) for the exponents they are given: those
        // whose columns all read entry v, k0 being 2^82 - 1 and k_j 2^82 - 1 or 0 as bit j - 1 of v is
        // set, those whose columns below the top all read entry v + 8, k0 being 1 and k_j 1 or 0, and
        // a random split
        int[] allOnes = { -1, -1, (1 << 18) - 1 };
        int[][][] ks = new int[17][][];
        for (int v = 0; v != 8; v++)
        {
            ks[v] = new int[][]{ Arrays.clone(allOnes), new int[3], new int[3], new int[3] };
            ks[v + 8] = new int[][]{ { 1, 0, 0 }, new int[3], new int[3], new int[3] };
            for (int j = 1; j != 4; j++)
            {
                if (((v >>> (j - 1)) & 1) != 0)
                {
                    ks[v][j] = Arrays.clone(allOnes);
                    ks[v + 8][j][0] = 1;
                }
            }
        }
        ks[16] = (int[][])decompose.invoke(null, new Object[]{
            BigIntegers.createRandomInRange(BigInteger.ZERO, n.subtract(BigInteger.ONE), random) });
        for (int i = 0; i != ks.length; i++)
        {
            BigInteger x = BigInteger.ZERO;
            for (int j = 3; j >= 0; j--)
            {
                x = x.multiply(lambda).add(Nat.toBigInteger(3, ks[i][j]));
            }
            isTrue("powSecure's columns over split " + i,
                splitPower.invoke(null, new Object[]{ table, m, ks[i] }).equals(h.pow(x.mod(n))));
        }

        // the columns read the table through lookup, which reads every entry whichever it returns: over a table
        // one entry short, they read past its end over a split whose columns all read entry 0. (This probe
        // follows checkFixedBaseExponentiation's, so its exception may have no stack trace: see readPastEndInLookup)
        checkReadsPastEnd("powSecure's columns read the entries they pick alone",
            "powSecure's columns read every entry through lookup", splitPower, null, new Object[]{
            Arrays.copyOfRange(table, 0, 15 * 96), m, new int[][]{ Arrays.clone(allOnes), new int[3], new int[3], new int[3] } },
            Fp12.class);

        // the split's draw, m and the entries the columns' lookups start at cannot show in the result, but their
        // draws can: 8 bytes for the split, 32 for m and one for each of the eighty-two lookups
        RecordingSource recording = new RecordingSource(null);
        try
        {
            CryptoServicesRegistrar.setSecureRandom(recording);
            g.powSecure(n.subtract(BigInteger.ONE));
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        isTrue("powSecure draws its blinding, its factor and the entries its lookups start at: "
            + recording.lengths(), "8 32 82".equals(recording.lengths()));

        // SM9Curve.blind: 320 bits, and sound for any value below 2^256
        BigInteger[] scalars = { BigInteger.ZERO, BigInteger.ONE, n.subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE), new BigInteger(256, random) };
        for (int i = 0; i != scalars.length; i++)
        {
            int[] words = (int[])blind.invoke(null, new Object[]{ scalars[i] });
            BigInteger blinded = Nat.toBigInteger(words.length, words);
            isTrue("a blinded scalar has 320 bits", words.length == 10 && blinded.bitLength() == 320);
            isTrue("and stands for the scalar", blinded.mod(n).equals(scalars[i].mod(n)));
        }

        // its value exactly where the carries of its fixed-width words run furthest: at the ends of the range the
        // multiplier r = ceil(2^319 / N) + s is drawn from, s being 0 or 2^63 - 1, and for the widest scalar
        BigInteger base = BigInteger.ONE.shiftLeft(319).add(n).subtract(BigInteger.ONE).divide(n);
        byte[][] blindEnds = { new byte[8], Hex.decode("ffffffffffffffff") };
        BigInteger[] widest = { BigInteger.ZERO, BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE) };
        for (int i = 0; i != blindEnds.length; i++)
        {
            for (int j = 0; j != widest.length; j++)
            {
                int[] words = (int[])withSource(new FixedSecureRandom(blindEnds[i]), blind, null, new Object[]{ widest[j] });
                BigInteger r = base.add(new BigInteger(1, blindEnds[i]).clearBit(63));
                isTrue("the blinding at the end of its range", Nat.toBigInteger(words.length, words).equals(widest[j].add(r.multiply(n))));
            }
        }

        // nor can the factor the tower's inversion blinds the norm it inverts with, but its draw can
        RecordingSource counting = new RecordingSource(random);
        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        withSource(counting, declaredMethod(fp2, "invert", new Class[0]), staticField(fp2, "ONE"), new Object[0]);
        isTrue("the F_p2 inversion draws its blinding factor", counting.draws >= 1);
    }

    // the four exponents of a split of e: k0 odd and below 2^82, the others below 2^81, and
    // k0 + k1 lambda + k2 lambda^2 + k3 lambda^3 = e mod N
    private void checkSplit(int[][] k, BigInteger e, BigInteger lambda)
    {
        BigInteger x = BigInteger.ZERO;
        for (int j = 3; j >= 0; j--)
        {
            BigInteger kj = Nat.toBigInteger(3, k[j]);
            isTrue("exponent " + j + " of the split of " + e.toString(16) + " is in range", kj.bitLength() <= (j == 0 ? 82 : 81));
            x = x.multiply(lambda).add(kj);
        }
        isTrue("the split of " + e.toString(16) + " has k0 odd", (k[0][0] & 1) != 0);
        isTrue("the split of " + e.toString(16) + " stands for it", x.mod(SM9Curve.N).equals(e));
    }

    // the determinant of a square matrix, by expansion along its first row
    private static BigInteger determinant(BigInteger[][] a)
    {
        if (a.length == 1)
        {
            return a[0][0];
        }
        BigInteger d = BigInteger.ZERO;
        for (int c = 0; c != a.length; c++)
        {
            BigInteger[][] minor = new BigInteger[a.length - 1][a.length - 1];
            for (int i = 1; i != a.length; i++)
            {
                for (int j = 0, k = 0; j != a.length; j++)
                {
                    if (j != c)
                    {
                        minor[i - 1][k++] = a[i][j];
                    }
                }
            }
            BigInteger term = a[0][c].multiply(determinant(minor));
            d = (c & 1) == 0 ? d.add(term) : d.subtract(term);
        }
        return d;
    }

    /**
     * powSecureFixedBase raises a base kept from call to call - a master public key's pairing value - by Lim
     * and Lee's comb over two tables of thirty-two powers of the base, the second the first's raised to 2^32,
     * that the first call makes and the base keeps: its results are held to pow, the tables to the powers they
     * are to hold and to being made once, without a draw, the comb, through reflection, over blinded exponents
     * chosen by their columns, its reads through Fp12.lookup, and each call's draws.
     */
    private void checkFixedBaseExponentiation()
        throws Exception
    {
        java.lang.reflect.Field kept = declaredField(Fp12.class, "combTables");
        java.lang.reflect.Field limbs = declaredField(Fp12.class, "limbs");
        java.lang.reflect.Method combPower = declaredMethod(Fp12.class, "combPower", new Class[]{ int[][].class, int[].class });
        java.lang.reflect.Method lookup = declaredMethod(Fp12.class, "lookup",
            new Class[]{ int[].class, int.class, int.class, int.class, int[].class });

        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N;
        BigInteger offset = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        Fp12 g = SM9Pairing.pairing(SM9Curve.P1, SM9Curve.P2);

        isTrue("a base has no tables before its first call", kept.get(g) == null);
        isTrue("the comb raises to 1", g.powSecureFixedBase(BigInteger.ONE).equals(g));
        int[][] tables = (int[][])kept.get(g);
        isTrue("the first call keeps two tables of 32 elements", tables != null && tables.length == 2
            && tables[0].length == 32 * 96 && tables[1].length == 32 * 96);
        g.powSecureFixedBase(n.subtract(BigInteger.ONE));
        isTrue("later calls read the tables kept", kept.get(g) == tables);

        // entry d of table j is g^((1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256) 2^(32 j)) for
        // d = d0 + 2d1 + ... + 16d4; none is 1, nor has a coefficient 0, as a random element of G_T has none
        for (int j = 0; j != 2; j++)
        {
            for (int d = 0; d != 32; d++)
            {
                BigInteger x = BigInteger.ONE;
                for (int i = 0; i != 5; i++)
                {
                    if (((d >>> i) & 1) != 0)
                    {
                        x = x.add(BigInteger.ONE.shiftLeft(64 * i));
                    }
                }
                isTrue("comb table " + j + " entry " + d, Arrays.areEqual(Arrays.copyOfRange(tables[j], d * 96, (d + 1) * 96),
                    (int[])limbs.get(g.pow(x.shiftLeft(32 * j)))));
                checkNoZeroElement("comb table " + j + " entry " + d + " has no coefficient 0", tables[j], d * 96, 96);
            }
        }

        // the results, at the ends of the exponent's range, around 2^64 - 1 and over random bases
        BigInteger[] exponents = { BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2),
            offset.subtract(BigInteger.ONE), offset, offset.add(BigInteger.ONE),
            n.subtract(offset).subtract(BigInteger.ONE), n.subtract(offset), n.subtract(BigInteger.valueOf(2)),
            n.subtract(BigInteger.ONE) };
        for (int i = 0; i != exponents.length; i++)
        {
            isTrue("powSecureFixedBase agrees with pow for " + exponents[i].toString(16),
                g.powSecureFixedBase(exponents[i]).equals(g.pow(exponents[i])));
        }
        for (int i = 0; i != 8; i++)
        {
            Fp12 h = g.pow(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
            BigInteger e = new BigInteger(256 - 32 * i, random).mod(n);
            Fp12 w = h.powSecureFixedBase(e);
            isTrue("powSecureFixedBase agrees with pow and powSecure over a random base at bit length "
                + e.bitLength(), w.equals(h.pow(e)) && w.equals(h.powSecure(e)));
        }

        // the comb itself gives g^(k + 2^64 - 1) for the blinded exponent k: here k whose columns are all 0, all
        // 31, each value in turn - upwards over the columns below 32, which it reads from the first table, and
        // downwards over the rest, from the second - all 0 below 32 and all 31 above, the other way round, and
        // the top bit alone
        int[][] ks = new int[6][10];
        Arrays.fill(ks[1], -1);
        for (int c = 0; c != 64; c++)
        {
            int[] values = { c < 32 ? c : 63 - c, c < 32 ? 0 : 31, c < 32 ? 31 : 0 };
            for (int v = 0; v != values.length; v++)
            {
                for (int i = 0; i != 5; i++)
                {
                    if (((values[v] >>> i) & 1) != 0)
                    {
                        int bit = c + 64 * i;
                        ks[2 + v][bit >>> 5] |= 1 << (bit & 31);
                    }
                }
            }
        }
        ks[5][9] = 1 << 31;
        for (int i = 0; i != ks.length; i++)
        {
            Fp12 want = g.pow(Nat.toBigInteger(10, ks[i]).add(offset));
            isTrue("the comb over blinded exponent " + i,
                combPower.invoke(null, new Object[]{ tables, Arrays.clone(ks[i]) }).equals(want));
        }

        // the comb reads each table through lookup, which reads every entry whichever it returns: with either
        // table one entry short, it reads past the end over an exponent whose columns are all 0, entry 0 being
        // the only one it picks. And lookup returns the entry asked for over tables of the sizes the tower
        // reads - this comb's columns, powSecure's and the pairing's (see checkLookup). (The comb's probes come
        // first, so that the first exception has a stack trace: see readPastEndInLookup)
        for (int j = 0; j != 2; j++)
        {
            int[][] shortTables = { tables[0], tables[1] };
            shortTables[j] = Arrays.copyOfRange(tables[j], 0, 31 * 96);
            checkReadsPastEnd("the comb read the entries it picks alone from table " + j, "the comb reads every entry of table "
                + j + " through lookup", combPower, null, new Object[]{ shortTables, new int[10] }, Fp12.class);
        }
        checkLookup(lookup, Fp12.class, 32, 96, true);
        checkLookup(lookup, Fp12.class, 16, 96, false);
        checkLookup(lookup, Fp12.class, 64, 96, false);

        // the tables are made from the base alone, without a draw, and each call draws its blinding, its factor
        // and the entries its lookups start at: 8 bytes, 32 and one for each of the sixty-four lookups
        java.lang.reflect.Method combTables = declaredMethod(Fp12.class, "combTables", new Class[0]);
        Fp12 h = g.pow(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
        RecordingSource recording = new RecordingSource(null);
        String made, called;
        try
        {
            CryptoServicesRegistrar.setSecureRandom(recording);
            combTables.invoke(h, new Object[0]);
            made = recording.lengths();
            recording.clear();
            h.powSecureFixedBase(n.subtract(BigInteger.ONE));
            called = recording.lengths();
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        isTrue("the comb's tables are made without a draw", made.length() == 0 && kept.get(h) != null);
        isTrue("powSecureFixedBase draws its blinding, its factor and the entries its lookups start at: "
            + called, "8 32 64".equals(called));
    }

    /**
     * A lookup of the tower's, G1's or G2's, over a table of random words of the given number of entries of
     * the given size: it returns the entry it is asked for wherever its scan starts - start is taken mod the
     * number of entries - and whatever the destination held. With probe set, it also reads every entry to do
     * so, from the entry it is told, wrapping round, having cleared the destination first: over a table one
     * entry short, the scan from entry s reaches the entries from s to the last one present, and then runs past
     * the end. Asked for entry 0 from entry 1, it leaves the destination cleared - where a scan from entry 0
     * whatever start is, one the other way round and one that does not clear the destination would not - and
     * asked for the entry it starts at, it leaves that entry, where a scan from the entry after it would not.
     * Those two probes come before the lookup's other calls here (see readPastEndInLookup).
     */
    private void checkLookup(java.lang.reflect.Method lookup, Class owner, int entries, int size, boolean probe)
        throws Exception
    {
        String name = owner.getName().substring(owner.getName().lastIndexOf('.') + 1) + ".lookup";
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        int[] table = new int[entries * size];
        for (int i = 0; i != table.length; i++)
        {
            table[i] = random.nextInt();
        }
        int[] z = new int[size];
        if (probe)
        {
            // over the short table: entry 0 from entry 1, reached only after the end, and the entry
            // the scan starts at, reached first
            int[] shortTable = Arrays.copyOfRange(table, 0, (entries - 1) * size);
            int[][] probes = { { 1, 0 }, { entries / 2, entries / 2 } };
            for (int i = 0; i != probes.length; i++)
            {
                int start = probes[i][0], d = probes[i][1];
                fillRandom(z, random);
                checkReadsPastEnd(name + " read entry " + d + " alone, from entry " + start, name + " reads every entry",
                    lookup, null, lookupArguments(lookup, shortTable, entries, size, d, start, z), owner);
                boolean reached = d >= start;
                isTrue(name + " from entry " + start + " reaches entry " + d + (reached ? " first" : " only after the end"),
                    Arrays.areEqual(z, reached ? Arrays.copyOfRange(table, d * size, (d + 1) * size) : new int[size]));
            }
        }

        int[] starts = { 0, 1, 3 - entries, entries / 2, entries - 1, entries, -1, -128, 127, random.nextInt() };
        for (int k = 0; k != starts.length; k++)
        {
            for (int d = 0; d != entries; d++)
            {
                fillRandom(z, random);
                lookup.invoke(null, lookupArguments(lookup, table, entries, size, d, starts[k], z));
                isTrue(name + " returns entry " + d + " from start " + starts[k],
                    Arrays.areEqual(z, Arrays.copyOfRange(table, d * size, (d + 1) * size)));
            }
        }
    }

    // the arguments of a call of lookup: the table, its number of entries, the size of an entry where
    // the lookup takes one - G1's - the entry asked for, the entry to start at and the destination
    private static Object[] lookupArguments(java.lang.reflect.Method lookup, int[] table, int entries, int size,
        int d, int start, int[] z)
    {
        if (lookup.getParameterTypes().length == 6)
        {
            return new Object[]{ table, Integers.valueOf(entries), Integers.valueOf(size), Integers.valueOf(d),
                Integers.valueOf(start), z };
        }
        return new Object[]{ table, Integers.valueOf(entries), Integers.valueOf(d), Integers.valueOf(start), z };
    }

    private static void fillRandom(int[] z, SecureRandom random)
    {
        for (int i = 0; i != z.length; i++)
        {
            z[i] = random.nextInt() | 1;
        }
    }

    /**
     * A source that records the length of each draw, as a list such as "8 32 64", and counts the draws: with
     * no source given, every byte 0x01, so that every draw is usable, and otherwise the given source's bytes.
     */
    private static class RecordingSource
        extends SecureRandom
    {
        private final StringBuffer lengths = new StringBuffer();
        private final SecureRandom source;
        private int draws;

        RecordingSource(SecureRandom source)
        {
            this.source = source;
        }

        public void nextBytes(byte[] bytes)
        {
            draws++;
            lengths.append(lengths.length() == 0 ? "" : " ").append(bytes.length);
            if (source == null)
            {
                Arrays.fill(bytes, (byte)1);
            }
            else
            {
                source.nextBytes(bytes);
            }
        }

        String lengths()
        {
            return lengths.toString();
        }

        void clear()
        {
            lengths.setLength(0);
            draws = 0;
        }
    }

    // m invoked on the arguments with source as the default random source, which is reset after
    private static Object withSource(SecureRandom source, java.lang.reflect.Method m, Object target, Object[] arguments)
        throws Exception
    {
        try
        {
            CryptoServicesRegistrar.setSecureRandom(source);
            return m.invoke(target, arguments);
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
    }

    /**
     * Whether t is an index out of range that the lookup of the given class ran into, rather than one
     * met elsewhere: an ArrayIndexOutOfBoundsException whose stack trace passes through that lookup,
     * or one with no stack trace and no message. HotSpot's compiled code throws the latter, an
     * instance it keeps, where the code has thrown before (-XX:+OmitStackTraceInFastThrow, the
     * default), so that once one probe has thrown from lookup, whether another's exception has a
     * stack trace depends on whether HotSpot, which compiles in the background, has compiled the code
     * again in the meantime. The first exception a method throws has one: a comb that read past the
     * end of its table outside lookup, scanning the table itself, would throw first with a stack
     * trace that does not pass through lookup. The trace is read from its printed form, which every
     * JDK the tests run on writes, rather than through getStackTrace(), which Java 1.3 lacks.
     */
    private static boolean readPastEndInLookup(Throwable t, Class c)
    {
        if (!(t instanceof ArrayIndexOutOfBoundsException))
        {
            return false;
        }
        java.io.StringWriter trace = new java.io.StringWriter();
        t.printStackTrace(new java.io.PrintWriter(trace, true));
        String frames = trace.toString();
        if (frames.indexOf("\tat ") < 0)
        {
            return t.getMessage() == null;
        }
        return frames.indexOf(c.getName() + ".lookup(") >= 0;
    }

    // m, invoked on the arguments, which hold a table one entry short, runs past its end in the lookup of owner
    private void checkReadsPastEnd(String failed, String reads, java.lang.reflect.Method m, Object target,
        Object[] arguments, Class owner)
        throws Exception
    {
        try
        {
            m.invoke(target, arguments);
            fail(failed);
        }
        catch (java.lang.reflect.InvocationTargetException ex)
        {
            isTrue(reads + ": " + ex.getTargetException(), readPastEndInLookup(ex.getTargetException(), owner));
        }
    }

    /**
     * The math layer's own draws - the random representatives the pairing, the G2 multiplication and the G2
     * subgroup check start from, the factors powSecure, powSecureFixedBase and G1's and G2's combs carry, the
     * one each inversion blinds with, the base of the pairing's random factor and the one the G1 field makes
     * for ECPoint.normalize() - come from the default source. A default source that yields only zeros or only
     * ones must not hang them, nor have them settle for a value every call would then take: each throws
     * IllegalStateException once its draws allowed are used up, and so do verification, the KGC's derivation
     * of a signing key and the normalisation of a G1 point, which reach them; and a base whose draw failed is
     * not kept. The sources here fail after 100,000 draws, so that a draw without a bound fails the test.
     */
    private void checkUnusableBlindingSource()
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger e = BigIntegers.createRandomInRange(BigInteger.ONE, SM9Curve.N.subtract(BigInteger.ONE), random);
        ECPoint p = SM9Curve.P1.multiply(e).normalize();
        Fp12 pairing = SM9Pairing.pairing(p, SM9Curve.P2);
        // an instance of p that keeps the comb's table, so that the comb over two tables below reaches its draws
        ECPoint withTable = copyG1(p);
        SM9Curve.sumOfTwoMultipliesSecure(SM9Curve.P1, e, withTable, e);
        SM9SigMasterPrivateKeyParameters master = new SM9SigMasterPrivateKeyParameters(e);
        SM9SigMasterPublicKeyParameters masterPublic = master.getPublicKeyParameters();
        byte[] identity = Strings.toByteArray("Alice");
        byte[] msg = Strings.toByteArray("message digest");
        byte[] sig = sign(new ParametersWithRandom(master.generateUserKey(identity), random), msg);

        // the base is drawn on the first call that needs it and kept: let the next call draw it
        java.lang.reflect.Field kept = declaredField(SM9Pairing.class, "kernelTable");
        java.lang.reflect.Method kernelTable = declaredMethod(SM9Pairing.class, "kernelTable", new Class[0]);
        kept.set(null, null);

        for (int fill = 0x00; fill <= 0xFF; fill += 0xFF)
        {
            final byte value = (byte)fill;
            final int[] draws = new int[1];
            String source = " from a source that yields only 0x" + Integer.toHexString(fill);
            try
            {
                CryptoServicesRegistrar.setSecureRandom(new SecureRandom()
                {
                    public void nextBytes(byte[] bytes)
                    {
                        if (++draws[0] > 100000)
                        {
                            throw new IllegalStateException("draws without end");
                        }
                        Arrays.fill(bytes, value);
                    }
                });
                try
                {
                    SM9Pairing.pairing(p, SM9Curve.P2);
                    fail("the pairing took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("the pairing", source, ex);
                }
                try
                {
                    pairing.powSecure(e);
                    fail("powSecure took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("powSecure", source, ex);
                }
                try
                {
                    pairing.powSecureFixedBase(e);
                    fail("powSecureFixedBase took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("powSecureFixedBase", source, ex);
                }
                try
                {
                    SM9Curve.P2.multiply(e);
                    fail("G2 multiplication took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("G2 multiplication", source, ex);
                }
                try
                {
                    SM9Curve.P2.isInSubgroup();
                    fail("the G2 subgroup check took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("the G2 subgroup check", source, ex);
                }
                SM9Signer verifier = new SM9Signer();
                verifier.init(false, new ParametersWithID(masterPublic, identity));
                verifier.update(msg, 0, msg.length);
                try
                {
                    verifier.verifySignature(sig);
                    fail("verification took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("verification", source, ex);
                }
                try
                {
                    SM9Curve.multiplySecure(SM9Curve.P1, e);
                    fail("G1's comb took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("G1's comb", source, ex);
                }
                try
                {
                    SM9Curve.sumOfTwoMultipliesSecure(SM9Curve.P1, e, withTable, e);
                    fail("G1's comb over two tables took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("G1's comb over two tables", source, ex);
                }
                try
                {
                    SM9Curve.P1.twice().normalize();
                    fail("the normalisation of a G1 point took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("the normalisation of a G1 point", source, ex);
                }
                try
                {
                    master.generateUserKey(identity);
                    fail("the KGC's derivation of a signing key took its draws" + source);
                }
                catch (IllegalStateException ex)
                {
                    checkUnusableSource("the KGC's derivation of a signing key", source, ex);
                }
                try
                {
                    kernelTable.invoke(null, new Object[0]);
                    fail("the base of the pairing's random factor was drawn" + source);
                }
                catch (java.lang.reflect.InvocationTargetException ex)
                {
                    checkUnusableSource("the base of the pairing's random factor", source, ex.getTargetException());
                }
                isTrue("a base whose draw failed is not kept", kept.get(null) == null);
            }
            finally
            {
                CryptoServicesRegistrar.setSecureRandom(null);
            }
        }

        isTrue("the pairing takes its draws from a working source again",
            SM9Pairing.pairing(p, SM9Curve.P2).equals(pairing));
        isTrue("and draws the base it had not kept", kept.get(null) != null);
    }

    private void checkUnusableSource(String what, String source, Throwable ex)
    {
        isTrue(what + " fails to draw" + source + ": " + ex,
            ex instanceof IllegalStateException
                && "SM9 arithmetic could not draw a usable random element".equals(ex.getMessage()));
    }

    /**
     * The final exponentiation raises to the BN parameter t in Karabina's compressed form, which the
     * pairing's results check only as a whole, so SM9Pairing.powT is held to pow(T) directly: over
     * random elements of the cyclotomic subgroup, in G_T and outside it, g and g^-1, and 1, whose
     * compressed coefficients are all 0.
     */
    private void checkExponentiationByT()
        throws Exception
    {
        java.lang.reflect.Method powT = declaredMethod(SM9Pairing.class, "powT", new Class[]{ Fp12.class });
        java.lang.reflect.Method frobenius2 = declaredMethod(SM9Pairing.class, "frobenius2", new Class[]{ Fp12.class });
        java.lang.reflect.Method frobenius6 = declaredMethod(SM9Pairing.class, "frobenius6", new Class[]{ Fp12.class });
        BigInteger t = (BigInteger)staticField(SM9Curve.class, "T");
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        Fp12 g = SM9Pairing.pairing(SM9Curve.P1, SM9Curve.P2);
        Fp12 one = (Fp12)staticField(Fp12.class, "ONE");

        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        Class fp4 = Class.forName("org.bouncycastle.math.ec.sm9.Fp4");
        java.lang.reflect.Constructor newFp2 = declaredConstructor(fp2, new Class[]{ BigInteger.class, BigInteger.class });
        java.lang.reflect.Constructor newFp4 = declaredConstructor(fp4, new Class[]{ fp2, fp2 });
        java.lang.reflect.Constructor newFp12 = declaredConstructor(Fp12.class, new Class[]{ fp4, fp4, fp4 });
        java.lang.reflect.Method invert = declaredMethod(Fp12.class, "invert", new Class[0]);

        Fp12[] ys = new Fp12[11];
        ys[0] = one;
        ys[1] = g;
        ys[2] = (Fp12)frobenius6.invoke(null, new Object[]{ g });
        for (int i = 3; i != ys.length; i += 2)
        {
            ys[i] = g.pow(new BigInteger(256, random));
            // z^((q^6 - 1)(q^2 + 1)) for a random z of F_p12, which is in the cyclotomic subgroup and
            // almost never in G_T
            Object[] c = new Object[3];
            for (int j = 0; j != 3; j++)
            {
                c[j] = newFp4.newInstance(new Object[]{
                    newFp2.newInstance(new Object[]{ new BigInteger(256, random), new BigInteger(256, random) }),
                    newFp2.newInstance(new Object[]{ new BigInteger(256, random), new BigInteger(256, random) }) });
            }
            Fp12 z = (Fp12)newFp12.newInstance(c);
            Fp12 z1 = ((Fp12)frobenius6.invoke(null, new Object[]{ z })).multiply((Fp12)invert.invoke(z, new Object[0]));
            ys[i + 1] = ((Fp12)frobenius2.invoke(null, new Object[]{ z1 })).multiply(z1);
        }
        for (int i = 0; i != ys.length; i++)
        {
            isTrue("powT agrees with pow(T), element " + i, powT.invoke(null, new Object[]{ ys[i] }).equals(ys[i].pow(t)));
        }
    }

    private static Object staticField(Class c, String name)
        throws Exception
    {
        return declaredField(c, name).get(null);
    }

    private static java.lang.reflect.Constructor declaredConstructor(Class c, Class[] parameters)
        throws Exception
    {
        java.lang.reflect.Constructor k = c.getDeclaredConstructor(parameters);
        k.setAccessible(true);
        return k;
    }

    /**
     * The SM9 G1 curve cannot decompress a point - its field has no square root - so its points refuse to
     * write a compressed encoding and the curve refuses to decode one, while the uncompressed form and the
     * point at infinity round-trip.
     */
    private void checkG1UncompressedOnly()
    {
        ECPoint p = SM9Curve.P1.multiply(BigInteger.valueOf(7)).normalize();
        try
        {
            p.getEncoded(true);
            fail("SM9 G1 point wrote a compressed encoding");
        }
        catch (UnsupportedOperationException e)
        {
            isTrue("SM9 G1 points have no compressed encoding".equals(e.getMessage()));
        }
        try
        {
            p.encodeTo(true, new byte[33], 0);
            fail("SM9 G1 point wrote a compressed encoding into a buffer");
        }
        catch (UnsupportedOperationException e)
        {
            isTrue("SM9 G1 points have no compressed encoding".equals(e.getMessage()));
        }

        byte[] uncompressed = p.getEncoded(false);
        byte[] compressed = new byte[33];
        compressed[0] = p.getAffineYCoord().testBitZero() ? (byte)0x03 : (byte)0x02;
        System.arraycopy(uncompressed, 1, compressed, 1, 32);
        try
        {
            SM9Curve.G1.decodePoint(compressed);
            fail("SM9 G1 decoded a compressed point");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("Invalid point compression".equals(e.getMessage()));
        }

        isTrue("SM9 G1 uncompressed round-trip", SM9Curve.G1.decodePoint(uncompressed).equals(p));
        ECPoint infinity = SM9Curve.G1.getInfinity();
        isTrue("SM9 G1 infinity encoding", Arrays.areEqual(new byte[1], infinity.getEncoded(true)));
        isTrue("SM9 G1 infinity round-trip", SM9Curve.G1.decodePoint(infinity.getEncoded(true)).isInfinity());

        // the raw x || y form of ciphertexts and encapsulations decodes only from 64 bytes the buffer has
        byte[] raw = SM9Curve.g1ToBytes(p);
        isTrue("SM9 G1 x || y round-trip", SM9Curve.g1FromBytes(raw, 0).equals(p));
        isTrue("SM9 G1 x || y round-trip at an offset",
            SM9Curve.g1FromBytes(Arrays.prepend(raw, (byte)0x55), 1).equals(p));
        byte[][] buffers = { Arrays.copyOfRange(raw, 0, 63), raw, raw, raw };
        int[] offsets = { 0, 1, -1, 65 };
        for (int i = 0; i != offsets.length; i++)
        {
            try
            {
                SM9Curve.g1FromBytes(buffers[i], offsets[i]);
                fail("SM9 G1 decoded x || y from " + buffers[i].length + " bytes at offset " + offsets[i]);
            }
            catch (IllegalArgumentException e)
            {
                isTrue("invalid SM9 G1 point encoding".equals(e.getMessage()));
            }
        }
    }

    /**
     * A point of order 13 on the twist curve E'(F_p2): y^2 = x^3 + 5u, which is on the
     * curve and is not in G2. Constructed as [N * h2 / 13]R for a point R found by
     * solving the curve equation at x = 1, where h2 = 2q - N is the twist's cofactor
     * and 13 divides it.
     */
    private static final String OFF_SUBGROUP_G2 =
          "0479BB36ADB803D88BE606FF3B88D7C4036F95BAE7931969F3F0F56E0C04"
        + "F380EA1257C42D5136EDD906F880EB6566F905DAFCA6E88B9FE1C3201AA5"
        + "813A3CCD207F5EA7F03E988993EAE50E1626542518BDA8384E67ED5A7963"
        + "A3F2A27AB2448E943824CC2BBE3FC9809C8E719008F6EC13465C4661AFFD"
        + "B70607B25B832E5A5B";

    /**
     * A point of order 1621 on the twist curve, the other small prime that divides h2, constructed
     * as the point of order 13 is, as [N * h2 / 1621]R for a point R of the curve.
     */
    private static final String OFF_SUBGROUP_G2_1621 =
          "043C9553124C4FC058665455ED29CF19F7990B527347542A5A8BF3840211"
        + "F3C2745530C32619FAB0A29E5E249E171665D14D4DDE5FAAC4AA7B472903"
        + "D220BBBB5E9C41F8C08205EDA558429E947FBAB6D696CEE9EDE70920DF15"
        + "820C3EABBC1D474CDB0393350BC7FBE6BA8150091C46C3782A1C5EA72F67"
        + "A68DA2D875F0A3EEED";

    /**
     * G2 is the order-N subgroup of the twist curve, whose cofactor h2 = 2q - N is a 256-bit composite, so
     * on-curve does not settle membership as it does on G1, and off the subgroup the pairing is not bilinear:
     * an encoded G2 point from outside the process is checked by [t + 1]P + pi([t]P) + pi^2([t]P) =
     * pi^3([2t]P), pi being the q-power Frobenius carried to the twist, which takes each point of G2 to its
     * q-th multiple, q being N + 6t^2.
     */
    private void checkG2Subgroup(SM9SigMasterPrivateKeyParameters master)
        throws Exception
    {
        byte[] offSubgroup = Hex.decode(OFF_SUBGROUP_G2);

        // it really is on the twist curve - this is a subgroup check, not an on-curve one
        isTrue("the crafted point is 129 bytes uncompressed", offSubgroup.length == 129 && offSubgroup[0] == 0x04);
        try
        {
            SM9G2Point.decode(offSubgroup);
            fail("SM9G2Point decoded a point outside the order-N subgroup");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 G2 point not in the order-N subgroup".equals(e.getMessage()));
        }

        // the check multiplies by t itself: blinded into t + r*N, as a secret scalar is, it would accept this
        // point for one value of r mod 13 in thirteen, so the point is refused under each of thirteen
        // consecutive values of the draw such a blinding makes first
        byte[] filler = new byte[4096];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(filler);
        try
        {
            for (int i = 0; i != 13; i++)
            {
                byte[] source = Arrays.clone(filler);
                Arrays.fill(source, 0, 8, (byte)0);
                source[7] = (byte)i;
                CryptoServicesRegistrar.setSecureRandom(new FixedSecureRandom(source));
                try
                {
                    SM9G2Point.decode(offSubgroup);
                    fail("SM9G2Point decoded a point outside the order-N subgroup under draw " + i);
                }
                catch (IllegalArgumentException e)
                {
                    isTrue("SM9 G2 point not in the order-N subgroup".equals(e.getMessage()));
                }
            }
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }

        // the test holds on G2 alone: the check refuses each multiple of this point, all of order 13, the first
        // multiples of a point of order 1621, the other small prime that divides h2, and the sums of each with
        // a point of G2, and accepts that point of G2 and the point at infinity
        SM9G2Point g = SM9Curve.P2.multiply(BigIntegers.createRandomInRange(BigInteger.ONE,
            SM9Curve.N.subtract(BigInteger.ONE), CryptoServicesRegistrar.getSecureRandom()));
        isTrue("a random point of G2 is in the subgroup", g.isInSubgroup());
        isTrue("the point at infinity is in the subgroup", SM9Curve.P2.multiply(SM9Curve.N).isInSubgroup());
        try
        {
            SM9G2Point.decode(Hex.decode(OFF_SUBGROUP_G2_1621));
            fail("SM9G2Point decoded a point of order 1621");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 G2 point not in the order-N subgroup".equals(e.getMessage()));
        }
        SM9G2Point[] small = { twistPoint(offSubgroup), twistPoint(Hex.decode(OFF_SUBGROUP_G2_1621)) };
        for (int s = 0; s != small.length; s++)
        {
            SM9G2Point m = small[s];
            for (int j = 1; j != 13; j++)
            {
                isTrue("[" + j + "] times a point of order " + (s == 0 ? 13 : 1621) + " is refused",
                    !m.isInSubgroup());
                isTrue("a point of G2 plus [" + j + "] times a point of order " + (s == 0 ? 13 : 1621)
                    + " is refused", !m.add(g).isInSubgroup());
                m = m.add(small[s]);
            }
            isTrue("[13] times a point of order 13 is infinity", s != 0 || m.isInfinity());
        }

        // the random representative the check starts its chain from cannot show in its answer, but its draw
        // can: under a source whose every draw is usable, the check draws what one random non-zero element of
        // F_p2 takes, and nothing more - it compares the two sides without inverting either
        RecordingSource usable = new RecordingSource(null);
        java.lang.reflect.Method randomNonZero = declaredMethod(Class.forName("org.bouncycastle.math.ec.sm9.Fp2"),
            "randomNonZero", new Class[0]);
        int element, check;
        try
        {
            CryptoServicesRegistrar.setSecureRandom(usable);
            randomNonZero.invoke(null, new Object[0]);
            element = usable.draws;
            usable.clear();
            isTrue("a point of G2 is in the subgroup under that source", g.isInSubgroup());
            check = usable.draws;
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        isTrue("the subgroup check draws the representative it starts from, and nothing more",
            element > 0 && check == element);

        checkG2SubgroupAdditions(g);

        // reachable as a signature master public key
        try
        {
            SM9SigMasterPublicKeyParameters.fromEncoded(offSubgroup);
            fail("SM9 signature master public key decoded outside the order-N subgroup");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 G2 point not in the order-N subgroup".equals(e.getMessage()));
        }

        // a coordinate at or above q is refused rather than reduced into the point its residue names, which
        // would give a G2 key further encodings
        SM9SigMasterPublicKeyParameters mpk = master.getPublicKeyParameters();
        for (int part = 0; part != 4; part++)
        {
            byte[] shifted = Arrays.clone(mpk.getEncoded());
            int off = 1 + part * 32;
            BigInteger q = SM9Curve.G1.getField().getCharacteristic();
            BigInteger raised = new BigInteger(1, Arrays.copyOfRange(shifted, off, off + 32)).add(q);
            if (raised.bitLength() > 256)
            {
                continue;   // the carry would not fit the 32-byte field, so there is no such encoding
            }
            System.arraycopy(BigIntegers.asUnsignedByteArray(32, raised), 0, shifted, off, 32);
            try
            {
                SM9G2Point.decode(shifted);
                fail("SM9G2Point decoded a coordinate at or above q, part " + part);
            }
            catch (IllegalArgumentException e)
            {
                isTrue("SM9 G2 point coordinate is not reduced modulo q".equals(e.getMessage()));
            }
        }

        // and the genuine master public key is in the subgroup, as is the generator; that a key rebuilt through
        // the check still verifies is held by checkVerificationProduct
        isTrue("a genuine master public key is in the subgroup", SM9G2Point.decode(mpk.getEncoded()).isInSubgroup());
        isTrue("the G2 generator is in the subgroup", SM9Curve.P2.isInSubgroup());
    }

    // the norm a0^2 + a0 a1 tr + a1^2 q of a0 + a1 pi, pi being the Frobenius on the twist, which
    // satisfies pi^2 - tr pi + q = 0 there
    private static BigInteger norm(BigInteger a0, BigInteger a1, BigInteger tr, BigInteger q)
    {
        return a0.multiply(a0).add(a0.multiply(a1).multiply(tr)).add(a1.multiply(a1).multiply(q));
    }

    /**
     * isInSubgroup forms [t]P and [t + 1]P by a chain of doublings and additions over the non-adjacent form
     * of t, adds pi([t]P) and pi^2([t]P) to [t + 1]P and compares the sum with pi^3([2t]P). Which operands its
     * additions and comparison can meet follows from the multipliers checked below. The chain is held, through
     * reflection, to the affine addition for a point of G2, for the multiples of a point of order 13, whose
     * additions meet an operand at infinity and two opposite operands, and for those of one of order 1621; and
     * the addition, the comparison and pi directly, on Jacobian representatives of points of G2, each with a
     * random Z.
     */
    private void checkG2SubgroupAdditions(SM9G2Point g)
        throws Exception
    {
        Class a = int[].class;
        java.lang.reflect.Method ladder = declaredMethod(SM9G2Point.class, "ladder", new Class[]{ a, int.class, a, a, a });
        java.lang.reflect.Method chain = declaredMethod(SM9G2Point.class, "multiplyByT", new Class[]{ a, a, a });
        java.lang.reflect.Method affine = declaredMethod(SM9G2Point.class, "affine", new Class[]{ a });
        java.lang.reflect.Method addAny = declaredMethod(SM9G2Point.class, "addAny", new Class[]{ a, a, a, a, a });
        java.lang.reflect.Method samePoint = declaredMethod(SM9G2Point.class, "samePoint", new Class[]{ a, a, a });
        java.lang.reflect.Method frobenius = declaredMethod(SM9G2Point.class, "frobenius", new Class[]{ a, a });
        int size = ((Integer)staticField(SM9G2Point.class, "POINT")).intValue();
        int z = ((Integer)staticField(SM9G2Point.class, "Z")).intValue();
        int[] t = new int[((Integer)staticField(SM9G2Point.class, "SCRATCH")).intValue()];
        BigInteger bn = (BigInteger)staticField(SM9Curve.class, "T");
        BigInteger q = SM9Curve.G1.getField().getCharacteristic();
        SM9G2Point infinity = SM9Curve.P2.multiply(SM9Curve.N);

        // the chain adds through add, which does not take two equal operands: each of its additions
        // adds [d]P, d being the digit, 1 or -1, to a running [k]P, which is [d]P only if the order
        // of P divides k - d, and the order of a point of the twist divides N h2, h2 = 2q - N, to
        // which each k - d, t - 1 for the last addition among them, is prime
        byte[] naf = (byte[])staticField(SM9Pairing.class, "T_NAF");
        BigInteger order = SM9Curve.N.multiply(q.shiftLeft(1).subtract(SM9Curve.N));
        BigInteger k = BigInteger.ONE;
        int additions = 0;
        for (int i = naf.length - 2; i >= 0; --i)
        {
            k = k.shiftLeft(1);
            if (naf[i] != 0)
            {
                BigInteger d = BigInteger.valueOf(naf[i]);
                isTrue("the chain's addition at digit " + i + " is never of two equal operands",
                    k.subtract(d).gcd(order).equals(BigInteger.ONE));
                k = k.add(d);
                additions++;
            }
        }
        isTrue("the chain runs over t's digits, from a top digit of 1, with ten additions",
            naf[naf.length - 1] == 1 && k.equals(bn) && additions == 10);
        isTrue("the chain's last addition is never of two equal operands",
            bn.subtract(BigInteger.ONE).gcd(order).equals(BigInteger.ONE));

        // nor, for any point of the twist but O, do the additions after the chain meet an operand at infinity or
        // two equal or opposite operands, or the comparison a side at infinity: each would need [t]P, [t + 1]P,
        // [2t]P or one of (t + 1) -+ t pi and (t + 1) + t pi -+ t pi^2 applied to P to be O, so the order of P
        // would divide the multiplier's norm, each prime to N h2 - where that of the test's own multiplier,
        // (t + 1) + t pi + t pi^2 - 2t pi^3, is a multiple of N, as every point of G2 passes
        BigInteger tr = bn.multiply(bn).multiply(BigInteger.valueOf(6)).add(BigInteger.ONE);
        BigInteger t1 = bn.add(BigInteger.ONE);
        BigInteger[][] multipliers = {
            { bn, BigInteger.ZERO }, { t1, BigInteger.ZERO }, { bn.shiftLeft(1), BigInteger.ZERO },
            { t1, bn.negate() }, { t1, bn },
            { t1.add(bn.multiply(q)), bn.subtract(bn.multiply(tr)) },
            { t1.subtract(bn.multiply(q)), bn.add(bn.multiply(tr)) } };
        for (int i = 0; i != multipliers.length; i++)
        {
            isTrue("multiplier " + i + " of the additions after the chain has a norm prime to N h2",
                norm(multipliers[i][0], multipliers[i][1], tr, q).gcd(order).equals(BigInteger.ONE));
        }
        BigInteger f0 = t1.subtract(bn.multiply(q)).add(bn.shiftLeft(1).multiply(tr).multiply(q));
        BigInteger f1 = bn.add(bn.multiply(tr)).subtract(bn.shiftLeft(1).multiply(tr.multiply(tr).subtract(q)));
        isTrue("the norm of the test's own multiplier is a multiple of N",
            norm(f0, f1, tr, q).mod(SM9Curve.N).signum() == 0);

        // the chain over t leaves [t]P and [t + 1]P, for a point of G2, and for the multiples of a
        // point of order 13 and of one of order 1621 as the affine addition forms them
        int[] r0 = new int[size], r1 = new int[size];
        chain.invoke(g, new Object[]{ r0, r1, t });
        isTrue("the chain leaves [t]P", affine.invoke(null, new Object[]{ r0 }).equals(g.multiply(bn)));
        isTrue("the chain leaves [t + 1]P", affine.invoke(null, new Object[]{ r1 }).equals(g.multiply(bn.add(BigInteger.ONE))));
        SM9G2Point[] small = { twistPoint(Hex.decode(OFF_SUBGROUP_G2)), twistPoint(Hex.decode(OFF_SUBGROUP_G2_1621)) };
        for (int s = 0; s != small.length; s++)
        {
            SM9G2Point m = small[s];
            for (int j = 1; j != 13; j++)
            {
                chain.invoke(m, new Object[]{ r0, r1, t });
                // t is even, so the affine addition forms [t + 1]m as [t]m + m after the same steps
                SM9G2Point tm = affineMultiple(m, bn);
                isTrue("the chain leaves [t]P and [t + 1]P for [" + j + "] times a point of order " + (s == 0 ? 13 : 1621),
                    affine.invoke(null, new Object[]{ r0 }).equals(tm) && affine.invoke(null, new Object[]{ r1 }).equals(tm.add(m)));
                m = m.add(small[s]);
            }
        }

        // over the one-bit scalar 1 it leaves a random representative of P, (x Z^2, y Z^3, Z)
        SM9G2Point h = g.add(SM9Curve.P2);
        int[] g1 = jacobian(ladder, g, size, t), g2 = jacobian(ladder, g, size, t);
        int[] minus = jacobian(ladder, g.multiply(SM9Curve.N.subtract(BigInteger.ONE)), size, t);
        int[] other = jacobian(ladder, h, size, t);
        isTrue("two representatives of a point differ", !Arrays.areEqual(g1, g2));
        isTrue("a representative stands for its point", affine.invoke(null, new Object[]{ g1 }).equals(g)
            && affine.invoke(null, new Object[]{ g2 }).equals(g));
        // the point at infinity as the doubling and the addition leave it, with X and Y not 0, and
        // with every coordinate 0
        int[] inf = Arrays.clone(g1);
        Arrays.fill(inf, z, size, 0);
        int[] zero = new int[size];

        // p, r and p + r: two representatives of one point, a point and its negation, the point at
        // infinity in either place and in both, and two points of G2 that are none of these
        Object[][] sums = {
            { g1, g2, g.add(g) }, { g1, minus, infinity }, { inf, g1, g }, { g1, inf, g }, { zero, g1, g },
            { g1, zero, g }, { inf, zero, infinity }, { zero, zero, infinity }, { g1, other, g.add(h) } };
        for (int i = 0; i != sums.length; i++)
        {
            int[] p = (int[])sums[i][0], r = (int[])sums[i][1];
            int[] sum = new int[size], pz = Arrays.clone(p), rz = Arrays.clone(r);
            addAny.invoke(null, new Object[]{ Arrays.clone(p), Arrays.clone(r), sum, new int[size], t });
            addAny.invoke(null, new Object[]{ pz, r, pz, new int[size], t });
            addAny.invoke(null, new Object[]{ p, rz, rz, new int[size], t });
            isTrue("addAny takes case " + i, affine.invoke(null, new Object[]{ sum }).equals(sums[i][2])
                && affine.invoke(null, new Object[]{ pz }).equals(sums[i][2])
                && affine.invoke(null, new Object[]{ rz }).equals(sums[i][2]));
        }

        // p, r and whether they are the same point: at infinity it is the same point whatever X and
        // Y are, and it is not the same point as any other, all-zero X and Y included
        Object[][] same = {
            { g1, g2, Boolean.TRUE }, { g1, g1, Boolean.TRUE }, { g1, minus, Boolean.FALSE }, { g1, other, Boolean.FALSE },
            { inf, zero, Boolean.TRUE }, { zero, zero, Boolean.TRUE }, { inf, inf, Boolean.TRUE }, { zero, g1, Boolean.FALSE },
            { g1, zero, Boolean.FALSE }, { inf, g1, Boolean.FALSE }, { g1, inf, Boolean.FALSE } };
        for (int i = 0; i != same.length; i++)
        {
            int bit = ((Integer)samePoint.invoke(null, new Object[]{ same[i][0], same[i][1], t })).intValue();
            isTrue("samePoint answers case " + i, bit == (((Boolean)same[i][2]).booleanValue() ? 1 : 0));
        }

        // pi takes a point of G2 to its q-th multiple, q mod N being 6t^2, and the point at infinity
        // to itself
        int[] image = new int[size], inPlace = Arrays.clone(g1), infImage = Arrays.clone(inf);
        frobenius.invoke(null, new Object[]{ g1, image });
        frobenius.invoke(null, new Object[]{ inPlace, inPlace });
        frobenius.invoke(null, new Object[]{ infImage, infImage });
        SM9G2Point expected = g.multiply(q.mod(SM9Curve.N));
        isTrue("pi takes a point of G2 to its q-th multiple", q.mod(SM9Curve.N).equals(bn.multiply(bn).multiply(BigInteger.valueOf(6)))
            && affine.invoke(null, new Object[]{ image }).equals(expected)
            && affine.invoke(null, new Object[]{ inPlace }).equals(expected));
        isTrue("pi takes the point at infinity to itself", ((SM9G2Point)affine.invoke(null, new Object[]{ infImage })).isInfinity());
    }

    // a Jacobian representative (x Z^2, y Z^3, Z) of p for a random Z, as SM9G2Point's ladder and its subgroup
    // check's chain start from: the ladder over the one-bit scalar 1 leaves it as [1]p
    private static int[] jacobian(java.lang.reflect.Method ladder, SM9G2Point p, int size, int[] t)
        throws Exception
    {
        int[] r0 = new int[size];
        ladder.invoke(p, new Object[]{ new int[]{ 1 }, Integers.valueOf(1), r0, new int[size], t });
        return r0;
    }

    // [k]p by the affine addition, which takes the point at infinity, two equal points and two
    // opposite ones each by a case of its own, for a point in G2 or not
    private static SM9G2Point affineMultiple(SM9G2Point p, BigInteger k)
    {
        SM9G2Point r = p.multiply(BigInteger.ZERO);
        for (int j = k.bitLength() - 1; j >= 0; --j)
        {
            r = r.add(r);
            if (k.testBit(j))
            {
                r = r.add(p);
            }
        }
        return r;
    }

    // the point of the twist curve an uncompressed encoding names, in G2 or not, through the package-private
    // constructor and coordinate decoding: decode() refuses one outside G2
    private static SM9G2Point twistPoint(byte[] enc)
        throws Exception
    {
        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        java.lang.reflect.Method coordinate = declaredMethod(SM9G2Point.class, "fp2FromBytes",
            new Class[]{ byte[].class, int.class });
        java.lang.reflect.Constructor point = declaredConstructor(SM9G2Point.class, new Class[]{ fp2, fp2 });
        return (SM9G2Point)point.newInstance(new Object[]{ coordinate.invoke(null, new Object[]{ enc, Integers.valueOf(1) }),
            coordinate.invoke(null, new Object[]{ enc, Integers.valueOf(65) }) });
    }

    /**
     * SM9G2Point.multiply works in Jacobian coordinates, over the scalar blinded into 320 bits, by the comb
     * for the generator and by the ladder, from a random representative of the point, for any other point -
     * and so passes through the point at infinity, and in the comb meets the point it adds, for some blinded
     * values of a small scalar. It is held to the affine addition, which has none of that, for the first
     * sixteen scalars and random ones, on the generator and on a random point of G2.
     */
    private void checkG2Multiply()
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        SM9G2Point[] points = { SM9Curve.P2, SM9Curve.P2.multiply(
            BigIntegers.createRandomInRange(BigInteger.ONE, SM9Curve.N.subtract(BigInteger.ONE), random)) };
        for (int p = 0; p != points.length; p++)
        {
            SM9G2Point sum = points[p];
            for (int k = 1; k <= 16; k++)
            {
                isTrue("[" + k + "]P agrees with the affine addition", points[p].multiply(BigInteger.valueOf(k)).equals(sum));
                sum = sum.add(points[p]);
            }
            for (int i = 0; i != 3; i++)
            {
                BigInteger k = new BigInteger(256, random);
                SM9G2Point r = affineMultiple(points[p], k);
                isTrue("[k]P agrees with the affine addition", points[p].multiply(k).equals(r));
            }
        }
    }

    /**
     * For P2, SM9G2Point.multiply runs Lim and Lee's comb over a table of thirty-two multiples of P2 and their
     * doubles that P2 keeps: its results are held to the ladder, which multiply runs for any other point - a
     * decoded copy of P2 among them - at the ends of the scalar's range, around 2^64 - 1 and at random; the
     * table to being made once, without a draw, and kept by P2 alone; its entries, the comb and its lookups
     * through checkComb - for a small scalar the blinding makes the running point meet the entry it adds about
     * once in thirty-two calls; and each call's draws.
     */
    private void checkG2FixedBaseMultiply()
        throws Exception
    {
        java.lang.reflect.Field kept = declaredField(SM9G2Point.class, "combTable");
        java.lang.reflect.Method combTable = declaredMethod(SM9G2Point.class, "combTable", new Class[0]);
        java.lang.reflect.Method comb = declaredMethod(SM9G2Point.class, "comb", new Class[]{ int[].class, int[].class });
        java.lang.reflect.Method lookup = declaredMethod(SM9G2Point.class, "lookup",
            new Class[]{ int[].class, int.class, int.class, int.class, int[].class });

        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N;
        BigInteger offset = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        SM9G2Point copy = SM9G2Point.decode(SM9Curve.P2.getEncoded());
        isTrue("a decoded copy of P2 is another instance", copy != SM9Curve.P2 && copy.equals(SM9Curve.P2));

        // the results, against the ladder the copy runs
        BigInteger[] scalars = { BigInteger.ONE, BigInteger.valueOf(2), BigInteger.valueOf(3),
            offset.subtract(BigInteger.ONE), offset, offset.add(BigInteger.ONE), n.subtract(offset).subtract(BigInteger.ONE),
            n.subtract(offset), n.subtract(BigInteger.valueOf(2)), n.subtract(BigInteger.ONE), BigInteger.ONE.shiftLeft(255) };
        for (int i = 0; i != scalars.length; i++)
        {
            isTrue("the comb agrees with the ladder for " + scalars[i].toString(16),
                SM9Curve.P2.multiply(scalars[i]).equals(copy.multiply(scalars[i])));
        }
        isTrue("the comb takes P2 to infinity by N", SM9Curve.P2.multiply(n).isInfinity());
        for (int i = 0; i != 8; i++)
        {
            BigInteger k = new BigInteger(256 - 32 * i, random).mod(n);
            isTrue("the comb agrees with the ladder at bit length " + k.bitLength(),
                SM9Curve.P2.multiply(k).equals(copy.multiply(k)));
        }
        isTrue("the copy keeps no table", kept.get(copy) == null);

        // the table P2 keeps, and one made for a fresh instance of the same point: made without a draw and kept
        int[] table = (int[])kept.get(SM9Curve.P2);
        isTrue("P2 keeps a table of 32 points and their doubles", table != null && table.length == 32 * 64);
        SM9G2Point fresh = twistPoint(SM9Curve.P2.getEncoded());
        RecordingSource counting = new RecordingSource(random);
        int[] made = (int[])withSource(counting, combTable, fresh, new Object[0]);
        isTrue("the comb's table is made without a draw", counting.draws == 0);
        isTrue("the table is kept", combTable.invoke(fresh, new Object[0]) == made && kept.get(fresh) == made);
        isTrue("the table is made the same way each time", Arrays.areEqual(made, table));
        SM9Curve.P2.multiply(n.subtract(BigInteger.ONE));
        isTrue("later calls read the table kept", kept.get(SM9Curve.P2) == table);
        checkComb(comb, null, table, copy, lookup);

        // each call draws its blinding, 8 bytes, the factor its entries are carried by, two elements of F_q of
        // 32, one byte for each of the sixty-four lookups and the inversion's factor, 32
        RecordingSource recording = new RecordingSource(null);
        try
        {
            CryptoServicesRegistrar.setSecureRandom(recording);
            SM9Curve.P2.multiply(BigInteger.valueOf(12345));
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        isTrue("the comb draws its blinding, its factor, the entries its lookups start at and the inversion's factor: "
            + recording.lengths(), "8 32 32 64 32".equals(recording.lengths()));
    }

    /**
     * Blinded scalars k, less 2^64 - 1, over which the combs for P1 and P2 - five bits in each of
     * sixty-four columns, over a table whose entry 0 is the point itself - meet the cases their
     * additions take: k whose columns below the last one or three are all 0, the entry they pick being
     * the point P itself. The running point, [2 s]P as the last column adds P, is at infinity there
     * when k = 2jN + 2 - 2^64, and is P itself when k = jN + 3 - 2^64 for an odd j, the sums being P
     * and [2]P; and after the third column from the end it is at infinity when k = 8jN + 8 - 2^64, and
     * meets P there when k = 4jN + 12 - 2^64 for an odd j, the sums being [7]P and [11]P
     * ({@link #COMB_CASE_MULTIPLES}). One in sixteen j gives such a k for the last column, one in
     * 4096 for the third from it. k = N - 2^64 + 1 has the running point meet the negation of the
     * entry the last column adds, and the sum is infinity.
     */
    private static BigInteger[] combCases()
    {
        BigInteger n = SM9Curve.N;
        long[][] shapes = { { 2, 2, 1 }, { 1, 3, 1 }, { 8, 8, 3 }, { 4, 12, 3 } };
        BigInteger[] cases = new BigInteger[shapes.length];
        for (int i = 0; i != shapes.length; i++)
        {
            int columns = (int)shapes[i][2], step = i % 2 == 0 ? 1 : 2;
            for (long j = 1; cases[i] == null; j += step)
            {
                BigInteger candidate = BigInteger.valueOf(shapes[i][0]).multiply(BigInteger.valueOf(j)).multiply(n)
                    .add(BigInteger.valueOf(shapes[i][1])).subtract(BigInteger.ONE.shiftLeft(64));
                if (lowColumnsZero(candidate, columns))
                {
                    cases[i] = candidate;
                }
            }
        }
        return cases;
    }

    // the multiples of the point that the combs give over the scalars combCases gives, and which of
    // those scalars have the running point meet the entry it adds, rather than pass through infinity
    private static final int[] COMB_CASE_MULTIPLES = { 1, 2, 7, 11 };
    private static final boolean[] COMB_CASE_MEETS = { false, true, false, true };

    // whether bits c + 64 i of k, for i from 0 to 4, are all 0 for each c below the given number of
    // columns
    private static boolean lowColumnsZero(BigInteger k, int columns)
    {
        for (int c = 0; c != columns; c++)
        {
            for (int i = 0; i != 5; i++)
            {
                if (k.testBit(c + 64 * i))
                {
                    return false;
                }
            }
        }
        return true;
    }

    // the i-th of a table's affine points of G2, each x || y in thirty-two limbs, as the point it holds:
    // in the comb's table, entry d is the (2d)th and its double the (2d + 1)th
    private static SM9G2Point tablePoint(int[] table, int i)
        throws Exception
    {
        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        java.lang.reflect.Constructor element = declaredConstructor(fp2, new Class[]{ int[].class });
        java.lang.reflect.Constructor point = declaredConstructor(SM9G2Point.class, new Class[]{ fp2, fp2 });
        return (SM9G2Point)point.newInstance(new Object[]{
            element.newInstance(new Object[]{ Arrays.copyOfRange(table, i * 32, i * 32 + 16) }),
            element.newInstance(new Object[]{ Arrays.copyOfRange(table, i * 32 + 16, i * 32 + 32) }) });
    }

    // the i-th of the affine points the comb's table of G1 or of G2 holds
    private static Object tablePoint(int[] table, boolean g1, int i)
        throws Exception
    {
        return g1 ? (Object)g1TablePoint(table, i) : tablePoint(table, i);
    }

    // [k]p for p a point of G1 or of G2, by its own multiply
    private static Object multiple(Object p, boolean g1, BigInteger k)
    {
        return g1 ? (Object)((ECPoint)p).multiply(k) : ((SM9G2Point)p).multiply(k);
    }

    // the arguments of G1's comb, which takes its curve first, or of G2's, whose curve is null and not passed
    private static Object[] combArguments(ECCurve curve, int[] table, int[] k)
    {
        return curve != null ? new Object[]{ curve, table, k } : new Object[]{ table, k };
    }

    /**
     * The comb of G1, given its curve, or of G2, given null, over p's table, through reflection: whether it is
     * G1's decides the size of the table's points, how p is multiplied, the class of its lookup and the
     * messages. Entry d of the table is [1 + d0 + d1 2^64 + d2 2^128 + d3 2^192 + d4 2^256]p for
     * d = d0 + 2d1 + ... + 16d4, followed by its double, none with an F_q component 0, as a random point has
     * none. The comb gives [k + 2^64 - 1]p for the blinded scalar k: here k whose columns are all 0, all 31,
     * each value in turn, or the top bit alone, and those combCases gives, and infinity for k = N - 2^64 + 1.
     * Its addition takes a running point equal to the entry it adds by the entry's double, which the table
     * holds beside it, forming none of its own: over a table whose doubles are replaced by their entries, it
     * gives the same points as before but where the running point meets the entry it adds. It reads its table
     * through lookup, which reads every entry whichever it returns: over a table one entry short, it reads past
     * the end for a k whose columns are all 0, entry 0 being the only one it picks.
     */
    private void checkComb(java.lang.reflect.Method comb, ECCurve curve, int[] table, Object p,
        java.lang.reflect.Method lookup)
        throws Exception
    {
        boolean g1 = curve != null;
        String what = g1 ? "the G1 comb" : "the comb";
        int size = g1 ? 16 : 32;
        Class owner = g1 ? Class.forName("org.bouncycastle.math.ec.sm9.SM9G1Multiplier") : SM9G2Point.class;
        BigInteger n = SM9Curve.N;
        BigInteger offset = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        for (int d = 0; d != 32; d++)
        {
            BigInteger m = BigInteger.ONE;
            for (int i = 0; i != 5; i++)
            {
                if (((d >>> i) & 1) != 0)
                {
                    m = m.add(BigInteger.ONE.shiftLeft(64 * i));
                }
            }
            isTrue("comb table entry " + d, tablePoint(table, g1, 2 * d).equals(multiple(p, g1, m.mod(n))));
            isTrue("comb table entry " + d + "'s double",
                tablePoint(table, g1, 2 * d + 1).equals(multiple(p, g1, m.shiftLeft(1).mod(n))));
            checkNoZeroElement("comb table entry " + d + " and its double have no " + (g1 ? "coordinate" : "F_q component")
                + " 0", table, 2 * size * d, 2 * size);
        }

        BigInteger each = BigInteger.ZERO;
        for (int c = 0; c != 64; c++)
        {
            for (int i = 0; i != 5; i++)
            {
                if ((((c & 31) >>> i) & 1) != 0)
                {
                    each = each.setBit(c + 64 * i);
                }
            }
        }
        BigInteger[] ks = { BigInteger.ZERO, BigInteger.ONE.shiftLeft(320).subtract(BigInteger.ONE), each,
            BigInteger.ONE.shiftLeft(319) };
        BigInteger[] cases = combCases();
        // the points the comb is to give, formed once for the table and for the table without its doubles
        Object[] want = new Object[ks.length + cases.length];
        for (int i = 0; i != want.length; i++)
        {
            want[i] = multiple(p, g1, i < ks.length ? ks[i].add(offset).mod(n)
                : BigInteger.valueOf(COMB_CASE_MULTIPLES[i - ks.length]));
        }
        for (int i = 0; i != ks.length; i++)
        {
            isTrue(what + " over blinded scalar " + i,
                comb.invoke(null, combArguments(curve, table, Nat.fromBigInteger(320, ks[i]))).equals(want[i]));
        }
        for (int i = 0; i != cases.length; i++)
        {
            isTrue(what + " through its case " + i, comb.invoke(null, combArguments(curve, table,
                Nat.fromBigInteger(320, cases[i]))).equals(want[ks.length + i]));
        }
        Object infinity = comb.invoke(null, combArguments(curve, table, Nat.fromBigInteger(320, n.subtract(offset))));
        isTrue(what + " to infinity", g1 ? ((ECPoint)infinity).isInfinity() : ((SM9G2Point)infinity).isInfinity());

        int[] undoubled = Arrays.clone(table);
        for (int d = 0; d != 32; d++)
        {
            System.arraycopy(table, 2 * size * d, undoubled, 2 * size * d + size, size);
        }
        for (int i = 0; i != ks.length; i++)
        {
            isTrue(what + " reads no double over blinded scalar " + i, comb.invoke(null, combArguments(curve, undoubled,
                Nat.fromBigInteger(320, ks[i]))).equals(want[i]));
        }
        for (int i = 0; i != cases.length; i++)
        {
            isTrue(what + " reads the double the table holds through its case " + i, COMB_CASE_MEETS[i] != comb.invoke(null,
                combArguments(curve, undoubled, Nat.fromBigInteger(320, cases[i]))).equals(want[ks.length + i]));
        }

        // this probe precedes checkLookup's, so that its exception has a stack trace (see readPastEndInLookup)
        checkReadsPastEnd(what + " read the entries it picks alone", what + " reads every entry through lookup", comb,
            null, combArguments(curve, Arrays.copyOfRange(table, 0, 62 * size), new int[10]), owner);
        checkLookup(lookup, owner, 32, 2 * size, true);
    }

    // each element of F_q in x from off to off + len, eight limbs as Fp holds one, is not 0
    private void checkNoZeroElement(String message, int[] x, int off, int len)
    {
        for (int j = off; j != off + len; j += 8)
        {
            int bits = 0;
            for (int w = 0; w != 8; w++)
            {
                bits |= x[j + w];
            }
            isTrue(message, bits != 0);
        }
    }

    /**
     * Verification computes w' = e(S, [h1]P2 + P_pub-s) g^h as e([h1]S, P2) e(S + [h]P1, P_pub-s), through
     * SM9Pairing.multiPair: the product is held to the pairings it stands for - a pair at infinity contributing
     * 1, a pair cancelling its negation - and a genuine signature's w' to the formula of GM/T 0044.2
     * recomputed here. S = -[h]P1 and the identity no key can be derived for, which put one of the pairs at
     * infinity, are refused rather than failing, as is a product of mismatched or foreign arguments. The lines
     * of a public point's Miller loop are kept with it, by verification and by the computation of the pairing
     * value the master public key fixes, and pairing() keeps none with its point, which may be a private key.
     */
    private void checkVerificationProduct(SM9SigMasterPrivateKeyParameters master, byte[] identity, byte[] msg)
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        BigInteger n = SM9Curve.N;
        ECPoint infinity = SM9Curve.G1.getInfinity();
        ECPoint p1 = SM9Curve.P1.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
        ECPoint p2 = SM9Curve.P1.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
        SM9G2Point q1 = SM9Curve.P2.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random));
        // multiPair keeps the lines of its public G2 points' Miller loops with them; pairing(), which the
        // private keys go through, keeps none, starting from a random representative of its point on every call
        java.lang.reflect.Field kept = declaredField(SM9G2Point.class, "millerLines");
        Fp12 e1 = SM9Pairing.pairing(p1, q1);
        isTrue("pairing() keeps no lines with its G2 point", kept.get(q1) == null);
        Fp12 e2 = SM9Pairing.pairing(p2, SM9Curve.P2);
        isTrue("multiPair of one pair is its pairing", SM9Pairing.multiPair(new ECPoint[]{ p1 }, new SM9G2Point[]{ q1 }).equals(e1));
        isTrue("multiPair of two pairs is the product of their pairings",
            SM9Pairing.multiPair(new ECPoint[]{ p1, p2 }, new SM9G2Point[]{ q1, SM9Curve.P2 }).equals(e1.multiply(e2)));
        isTrue("a pair at infinity contributes 1",
            SM9Pairing.multiPair(new ECPoint[]{ infinity, p2 }, new SM9G2Point[]{ q1, SM9Curve.P2 }).equals(e2));
        Fp12 one = SM9Pairing.multiPair(new ECPoint[]{ p1, p1.negate() }, new SM9G2Point[]{ q1, q1 });
        isTrue("a pair and its negation cancel", one.equals(SM9Pairing.multiPair(new ECPoint[0], new SM9G2Point[0])));
        try
        {
            SM9Pairing.multiPair(new ECPoint[]{ p1 }, new SM9G2Point[]{ q1, q1 });
            fail("multiPair took more G2 points than G1 points");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 multi-pairing needs as many G1 points as G2 points".equals(e.getMessage()));
        }
        try
        {
            SM9Pairing.multiPair(new ECPoint[]{ CustomNamedCurves.getByName("P-256").getG() }, new SM9G2Point[]{ q1 });
            fail("multiPair took a point of another curve");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 pairing first argument is not a point of G1".equals(e.getMessage()));
        }

        // a genuine signature's w' by the standard's own formula
        SM9SigMasterPublicKeyParameters pub = master.getPublicKeyParameters();
        byte[] sig = sign(new ParametersWithRandom(master.generateUserKey(identity), random), msg);
        BigInteger h = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
        ECPoint s = SM9Curve.G1.decodePoint(Arrays.copyOfRange(sig, 32, 97));
        BigInteger h1 = SM9Sm3.h1(Arrays.append(identity, SM9SigMasterPrivateKeyParameters.HID), n);
        Fp12 standard = SM9Pairing.pairing(s, SM9Curve.P2.multiply(h1).add(pub.getPointG2()))
            .multiply(pub.pairingWithP1().pow(h));
        Fp12 product = SM9Pairing.multiPair(new ECPoint[]{ s.multiply(h1), s.add(SM9Curve.P1.multiply(h)) },
            new SM9G2Point[]{ SM9Curve.P2, pub.getPointG2() });
        isTrue("the product is the standard's w'", product.equals(standard));
        isTrue("and the genuine signature verifies", verify(pub, identity, msg, sig));

        // S + [h]P1 at infinity
        byte[] cancelling = Arrays.concatenate(Arrays.copyOfRange(sig, 0, 32),
            SM9Curve.P1.multiply(h).negate().normalize().getEncoded(false));
        isTrue("S = -[h]P1 is refused", !verify(pub, identity, msg, cancelling));

        // [h1]P2 + P_pub-s at infinity: the identity no key can be derived for under this master key
        SM9SigMasterPrivateKeyParameters degenerate = new SM9SigMasterPrivateKeyParameters(n.subtract(h1));
        isTrue("a signature under the identity no key can be derived for is refused",
            !verify(degenerate.getPublicKeyParameters(), identity, msg, sig));

        // verification keeps the lines of the master public key it is given - a key rebuilt through the G2
        // subgroup check - as does computing the fixed pairing, whose arguments are public
        SM9SigMasterPublicKeyParameters verifying = SM9SigMasterPublicKeyParameters.fromEncoded(pub.getEncoded());
        SM9SigMasterPublicKeyParameters signing = SM9SigMasterPublicKeyParameters.fromEncoded(pub.getEncoded());
        isTrue("a decoded master public key keeps no lines",
            kept.get(verifying.getPointG2()) == null && kept.get(signing.getPointG2()) == null);
        isTrue("verification keeps the master public key's lines",
            verify(verifying, identity, msg, sig) && kept.get(verifying.getPointG2()) != null);
        isTrue("and P2's", kept.get(SM9Curve.P2) != null);
        isTrue("computing the fixed pairing keeps the master public key's lines",
            signing.pairingWithP1().equals(pub.pairingWithP1()) && kept.get(signing.getPointG2()) != null);
    }

    /**
     * The Miller loop's doubling and addition work in homogeneous projective coordinates, (X, Y, Z) standing
     * for (X/Z, Y/Z): they are held to the affine doubling and addition of points of G2, from random
     * representatives of the point and from Z = 1, as the pairing and multiPair start from those, and the lines
     * they return to the tangent and the chord up to the factor of F_p2 the loop takes them times:
     * c0 + cY yP v - cX xP w^2 is cY ((lambda x - y) + yP v - lambda xP w^2) for the slope lambda, through
     * (x, y) for the tangent at T and through Q = (x2, y2) for the chord. The pairing is held to drawing the
     * random Z its loop starts from, and the loop to running over the non-adjacent form of 6t + 2, neither of
     * which its value can show.
     */
    private void checkMillerLines()
        throws Exception
    {
        Class fp2 = Class.forName("org.bouncycastle.math.ec.sm9.Fp2");
        Class a = int[].class, n = int.class;
        java.lang.reflect.Method lineDouble = declaredMethod(SM9Pairing.class, "lineDouble", new Class[]{ a, a, n, a });
        java.lang.reflect.Method lineAdd = declaredMethod(SM9Pairing.class, "lineAdd", new Class[]{ a, a, a, a, n, a });
        int scratch = ((Integer)staticField(SM9Pairing.class, "LINE_SCRATCH")).intValue();
        java.lang.reflect.Method draw = declaredMethod(fp2, "randomNonZero", new Class[0]);
        java.lang.reflect.Method mul = declaredMethod(fp2, "multiply", new Class[]{ fp2 });
        java.lang.reflect.Method sub = declaredMethod(fp2, "subtract", new Class[]{ fp2 });
        java.lang.reflect.Constructor newFp2 = declaredConstructor(fp2, new Class[]{ BigInteger.class, BigInteger.class });
        java.lang.reflect.Constructor fromLimbs = declaredConstructor(fp2, new Class[]{ a });
        java.lang.reflect.Field limbs = declaredField(fp2, "limbs");
        java.lang.reflect.Field fx = declaredField(SM9G2Point.class, "x");
        java.lang.reflect.Field fy = declaredField(SM9G2Point.class, "y");
        Object one = newFp2.newInstance(new Object[]{ BigInteger.ONE, BigInteger.ZERO });
        Object two = newFp2.newInstance(new Object[]{ BigInteger.valueOf(2), BigInteger.ZERO });
        Object three = newFp2.newInstance(new Object[]{ BigInteger.valueOf(3), BigInteger.ZERO });
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        for (int i = 0; i != 16; i++)
        {
            SM9G2Point p = SM9Curve.P2.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, SM9Curve.N.subtract(BigInteger.ONE), random));
            SM9G2Point q = SM9Curve.P2.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, SM9Curve.N.subtract(BigInteger.ONE), random));
            Object x = fx.get(p), y = fy.get(p), x2 = fx.get(q), y2 = fy.get(q);
            for (int k = 0; k != 2; k++)
            {
                // (x Z, y Z, Z), for a random Z, or Z = 1; the line is written after one already there
                Object z = k == 0 ? draw.invoke(null, new Object[0]) : one;
                int[] t = homogeneous(limbs, mul.invoke(x, new Object[]{ z }), mul.invoke(y, new Object[]{ z }), z);
                int[] l = new int[96];
                lineDouble.invoke(null, new Object[]{ t, l, Integers.valueOf(48), new int[scratch] });
                Object[] c = { fp2At(fromLimbs, l, 48), fp2At(fromLimbs, l, 64), fp2At(fromLimbs, l, 80) };
                SM9G2Point d = p.add(p);
                isTrue("lineDouble doubles, case " + i + "." + k,
                    mul.invoke(fx.get(d), new Object[]{ fp2At(fromLimbs, t, 32) }).equals(fp2At(fromLimbs, t, 0))
                    && mul.invoke(fy.get(d), new Object[]{ fp2At(fromLimbs, t, 32) }).equals(fp2At(fromLimbs, t, 16)));
                // lambda = 3x^2 / 2y: cX 2y = cY 3x^2, and c0 2y = cY (3x^3 - 2y^2)
                Object x2x = mul.invoke(x, new Object[]{ x });
                Object y2y = mul.invoke(two, new Object[]{ y });
                isTrue("lineDouble's line is the tangent, case " + i + "." + k,
                    mul.invoke(c[2], new Object[]{ y2y }).equals(mul.invoke(c[1], new Object[]{ mul.invoke(three, new Object[]{ x2x }) }))
                    && mul.invoke(c[0], new Object[]{ y2y }).equals(mul.invoke(c[1], new Object[]{ sub.invoke(
                        mul.invoke(three, new Object[]{ mul.invoke(x2x, new Object[]{ x }) }),
                        new Object[]{ mul.invoke(y2y, new Object[]{ y }) }) })));

                t = homogeneous(limbs, mul.invoke(x, new Object[]{ z }), mul.invoke(y, new Object[]{ z }), z);
                lineAdd.invoke(null, new Object[]{ t, limbs.get(x2), limbs.get(y2), l, Integers.valueOf(48), new int[scratch] });
                c = new Object[]{ fp2At(fromLimbs, l, 48), fp2At(fromLimbs, l, 64), fp2At(fromLimbs, l, 80) };
                SM9G2Point s = p.add(q);
                isTrue("lineAdd adds, case " + i + "." + k,
                    mul.invoke(fx.get(s), new Object[]{ fp2At(fromLimbs, t, 32) }).equals(fp2At(fromLimbs, t, 0))
                    && mul.invoke(fy.get(s), new Object[]{ fp2At(fromLimbs, t, 32) }).equals(fp2At(fromLimbs, t, 16)));
                // lambda = (y2 - y) / (x2 - x): cX (x2 - x) = cY (y2 - y), and
                // c0 (x2 - x) = cY ((y2 - y) x2 - (x2 - x) y2)
                Object dx = sub.invoke(x2, new Object[]{ x }), dy = sub.invoke(y2, new Object[]{ y });
                isTrue("lineAdd's line is the chord, case " + i + "." + k,
                    mul.invoke(c[2], new Object[]{ dx }).equals(mul.invoke(c[1], new Object[]{ dy }))
                    && mul.invoke(c[0], new Object[]{ dx }).equals(mul.invoke(c[1], new Object[]{ sub.invoke(
                        mul.invoke(dy, new Object[]{ x2 }), new Object[]{ mul.invoke(dx, new Object[]{ y2 }) }) })));
            }
        }

        // the loop runs over the non-adjacent form of 6t + 2, whose sixty-five digits below the top one have
        // ten that are not 0, five of them -1, where its binary form has fifteen bits set below the top one: a
        // tangent for each digit, a line through Q or -Q for each that is not 0 and the Frobenius tail's two
        // make seventy-seven lines, which P2 keeps once it has been paired over
        BigInteger loop = (BigInteger)staticField(SM9Curve.class, "LOOP");
        int digits = 0, nonZero = 0, negative = 0;
        for (BigInteger k = loop; k.signum() > 0; k = k.shiftRight(1), digits++)
        {
            if (k.testBit(0))
            {
                // the digit is 2 - (k mod 4): 1 or -1, and k - digit is a multiple of 4
                boolean minus = k.testBit(1);
                k = minus ? k.add(BigInteger.ONE) : k.subtract(BigInteger.ONE);
                nonZero++;
                negative += minus ? 1 : 0;
            }
        }
        isTrue("6t + 2 has sixty-six digits in non-adjacent form, eleven of them not 0, five -1: " + digits + ", "
            + nonZero + ", " + negative, digits == 66 && nonZero == 11 && negative == 5 && loop.bitCount() == 16);
        SM9Pairing.multiPair(new ECPoint[]{ SM9Curve.P1 }, new SM9G2Point[]{ SM9Curve.P2 });
        java.lang.reflect.Field kept = declaredField(SM9G2Point.class, "millerLines");
        int lines = ((int[])kept.get(SM9Curve.P2)).length / ((Integer)staticField(SM9Pairing.class, "LINE")).intValue();
        isTrue("the Miller loop takes " + (digits - 1) + " tangents, " + (nonZero - 1) + " lines through Q or -Q and 2 "
            + "Frobenius lines: " + lines, lines == (digits - 1) + (nonZero - 1) + 2);

        // the random Z the pairing's loop starts from cannot show in the pairing's value, but its draw can:
        // under a source whose every draw is usable, a pairing draws what its final exponentiation draws and
        // one random non-zero element of F_p2 besides. The pairing made first, from the default source, leaves
        // the final exponentiation's own table made, so that neither count includes it
        java.lang.reflect.Method finalExponentiation = declaredMethod(SM9Pairing.class, "finalExponentiation",
            new Class[]{ Fp12.class });
        SM9G2Point q = SM9Curve.P2.multiply(BigIntegers.createRandomInRange(BigInteger.ONE, SM9Curve.N.subtract(BigInteger.ONE), random));
        Fp12 g = SM9Pairing.pairing(SM9Curve.P1, q);
        RecordingSource usable = new RecordingSource(null);
        int element, exponentiation, pairing;
        try
        {
            CryptoServicesRegistrar.setSecureRandom(usable);
            draw.invoke(null, new Object[0]);
            element = usable.draws;
            usable.clear();
            finalExponentiation.invoke(null, new Object[]{ g });
            exponentiation = usable.draws;
            usable.clear();
            isTrue("the pairing under that source", g.equals(SM9Pairing.pairing(SM9Curve.P1, q)));
            pairing = usable.draws;
        }
        finally
        {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
        isTrue("the pairing draws the random representative its loop starts from: " + pairing + " draws against "
            + exponentiation + " + " + element, element > 0 && pairing == exponentiation + element);
    }

    // (X, Y, Z) as the Miller loop's lines take T, from the limbs of three elements of F_p2
    private static int[] homogeneous(java.lang.reflect.Field limbs, Object x, Object y, Object z)
        throws Exception
    {
        int[] t = new int[48];
        System.arraycopy((int[])limbs.get(x), 0, t, 0, 16);
        System.arraycopy((int[])limbs.get(y), 0, t, 16, 16);
        System.arraycopy((int[])limbs.get(z), 0, t, 32, 16);
        return t;
    }

    // the element of F_p2 whose limbs are the sixteen of x from off
    private static Object fp2At(java.lang.reflect.Constructor fromLimbs, int[] x, int off)
        throws Exception
    {
        return fromLimbs.newInstance(new Object[]{ Arrays.copyOfRange(x, off, off + 16) });
    }

    private static boolean verify(SM9SigMasterPublicKeyParameters pub, byte[] identity, byte[] msg, byte[] sig)
    {
        SM9Signer verifier = new SM9Signer();
        verifier.init(false, new ParametersWithID(pub, identity));
        verifier.update(msg, 0, msg.length);
        return verifier.verifySignature(sig);
    }

    /**
     * The R-ate pairing itself, against the two G_T values the standard prints:
     * g = e(P1, P_pub-s) and w = g^r. Without these the pairing is only checked
     * indirectly, through the signature components.
     */
    private void checkPairingValues(Map v, SM9SigMasterPrivateKeyParameters master)
    {
        Fp12 g = SM9Pairing.pairing(SM9Curve.P1, master.getPublicKeyParameters().getPointG2());
        isTrue("SM9 pairing g = e(P1, Ppub-s)",
            Arrays.areEqual(SM9Pairing.toBytes(g), SM9Vectors.hex(v, "g_GT")));

        // the master public key keeps the same value, computed once, for the signer and the
        // verifier to take rather than pairing afresh on every initialisation
        SM9SigMasterPublicKeyParameters masterPublic = master.getPublicKeyParameters();
        isTrue("the master public key keeps e(P1, Ppub-s)",
            masterPublic.pairingWithP1() == masterPublic.pairingWithP1() && masterPublic.pairingWithP1().equals(g));

        Fp12 w = g.pow(new BigInteger((String)v.get("r"), 16));
        isTrue("SM9 pairing w = g^r", Arrays.areEqual(SM9Pairing.toBytes(w), SM9Vectors.hex(v, "w_GT")));

        // powSecure agrees with pow for exponents of every width and at the ends of the exponent's range
        BigInteger[] exponents = { BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(0x5A), BigInteger.ONE.shiftLeft(63),
            BigInteger.ONE.shiftLeft(255), SM9Curve.N.subtract(BigInteger.ONE), new BigInteger((String)v.get("r"), 16) };
        for (int i = 0; i != exponents.length; i++)
        {
            isTrue("SM9 powSecure agrees with pow at bit length " + exponents[i].bitLength(),
                g.powSecure(exponents[i]).equals(g.pow(exponents[i])));
        }
        // two calls on one exponent draw different blinding factors and still agree
        isTrue("SM9 powSecure is deterministic in its result",
            g.powSecure(SM9Curve.N.subtract(BigInteger.ONE))
                .equals(g.powSecure(SM9Curve.N.subtract(BigInteger.ONE))));
    }

    private static byte[] f32(BigInteger v)
    {
        return BigIntegers.asUnsignedByteArray(32, v);
    }

    /**
     * The same G1 point in the hybrid form 0x06 / 0x07 || x || y, whose prefix repeats y's
     * parity - the general point decoder checks the two agree, so the prefix follows y.
     */
    private static byte[] toHybrid(byte[] uncompressed)
    {
        byte[] hybrid = Arrays.clone(uncompressed);
        hybrid[0] = (byte)(((uncompressed[uncompressed.length - 1] & 1) == 0) ? 0x06 : 0x07);
        return hybrid;
    }

    public static void main(String[] args)
    {
        runTest(new SM9SignerTest());
    }
}
