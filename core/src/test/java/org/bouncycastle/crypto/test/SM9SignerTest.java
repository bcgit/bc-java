package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigUserKeyParametersGenerator;
import org.bouncycastle.crypto.signers.SM9Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Known-answer test for the SM9 digital signature algorithm (GM/T 0044.2-2016)
 * against the GM/T 0044.5-2016 Annex A vector (crypto/sm9/sm9_signature.txt):
 * the signature components h and S are reproduced byte-for-byte, verification
 * accepts, and a tampered message is rejected. Also checks a zero-length
 * message signs and verifies (the signer's l = 0 retry is a scalar test, so -
 * unlike the SM9 stream cipher's K1 check - an empty message is well-defined).
 */
public class SM9SignerTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9Signer";
    }

    private Map loadVectors(String fileName)
        throws Exception
    {
        Map m = new HashMap();
        BufferedReader br = new BufferedReader(
            new InputStreamReader(TestResourceFinder.findTestResource("crypto/sm9", fileName)));
        try
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq > 0)
                {
                    m.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
        }
        finally
        {
            br.close();
        }
        return m;
    }

    private byte[] hex(Map v, String key)
    {
        return Hex.decode((String)v.get(key));
    }

    public void performTest()
        throws Exception
    {
        Map v = loadVectors("sm9_signature.txt");
        BigInteger ks = new BigInteger((String)v.get("ks"), 16);
        byte[] identity = hex(v, "IDA");
        byte[] msg = hex(v, "M");

        SM9SigMasterPrivateKeyParameters master = new SM9SigMasterPrivateKeyParameters(ks);
        // derive through the KGC extraction interface (hid = 0x01 applied internally)
        SM9SigUserKeyParametersGenerator kgc = master;
        SM9SigPrivateKeyParameters userKey = kgc.generateUserKey(identity);

        // the domain parameters, generators, derived keys and pairing values the
        // standard prints alongside the signature itself (GM/T 0044.5-2016 Annex A)
        checkDomainParameters(v);
        checkKeyDerivation(v, master, userKey);
        checkPairingValues(v, master);

        SM9Signer signer = new SM9Signer();
        signer.init(true, new ParametersWithRandom(userKey, new TestRandomBigInteger(256, hex(v, "r"))));
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();

        // sig = h(32) || 0x04 || Sx(32) || Sy(32)
        isTrue("SM9 signature h", Arrays.areEqual(Arrays.copyOfRange(sig, 0, 32), hex(v, "h")));
        isTrue("SM9 signature S uncompressed prefix", sig[32] == (byte)0x04);
        isTrue("SM9 signature Sx", Arrays.areEqual(Arrays.copyOfRange(sig, 33, 65), hex(v, "Sx")));
        isTrue("SM9 signature Sy", Arrays.areEqual(Arrays.copyOfRange(sig, 65, 97), hex(v, "Sy")));

        SM9Signer verifier = new SM9Signer();
        verifier.init(false, new ParametersWithID(master.getPublicKeyParameters(), identity));
        verifier.update(msg, 0, msg.length);
        isTrue("SM9 signature verify", verifier.verifySignature(sig));

        SM9Signer tampered = new SM9Signer();
        tampered.init(false, new ParametersWithID(master.getPublicKeyParameters(), identity));
        byte[] bad = Arrays.clone(msg);
        bad[0] ^= 0x01;
        tampered.update(bad, 0, bad.length);
        isTrue("SM9 signature rejects tampered message", !tampered.verifySignature(sig));

        // a zero-length message must sign and verify - the h = H2(M || w) hash and the
        // scalar l = (r - h) mod N retry are both well-defined for an empty M
        SM9Signer emptySigner = new SM9Signer();
        emptySigner.init(true, new ParametersWithRandom(userKey, CryptoServicesRegistrar.getSecureRandom()));
        byte[] emptySig = emptySigner.generateSignature();

        SM9Signer emptyVerifier = new SM9Signer();
        emptyVerifier.init(false, new ParametersWithID(master.getPublicKeyParameters(), identity));
        isTrue("SM9 zero-length message verifies", emptyVerifier.verifySignature(emptySig));

        SM9Signer emptyWrong = new SM9Signer();
        emptyWrong.init(false, new ParametersWithID(master.getPublicKeyParameters(), identity));
        emptyWrong.update((byte)0x00);
        isTrue("SM9 zero-length signature does not verify a non-empty message",
            !emptyWrong.verifySignature(emptySig));
    }

    /**
     * The curve order and the two group generators printed by the standard.
     */
    private void checkDomainParameters(Map v)
    {
        isTrue("SM9 curve order N", Arrays.areEqual(f32(SM9Curve.N), hex(v, "N")));

        ECPoint p1 = SM9Curve.P1.normalize();
        isTrue("SM9 generator P1.x",
            Arrays.areEqual(f32(p1.getAffineXCoord().toBigInteger()), hex(v, "P1x")));
        isTrue("SM9 generator P1.y",
            Arrays.areEqual(f32(p1.getAffineYCoord().toBigInteger()), hex(v, "P1y")));

        // G2 points serialize as 0x04 || x_hi || x_lo || y_hi || y_lo, each F_p2
        // coordinate high-dimension (u-coefficient) first
        isTrue("SM9 generator P2", Arrays.areEqual(SM9Curve.P2.getEncoded(),
            g2(v, "P2x_hi", "P2x_lo", "P2y_hi", "P2y_lo")));
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
            g2(v, "Ppubsx_hi", "Ppubsx_lo", "Ppubsy_hi", "Ppubsy_lo")));

        ECPoint ds = userKey.getPrivatePoint().normalize();
        isTrue("SM9 user signing key dsA.x",
            Arrays.areEqual(f32(ds.getAffineXCoord().toBigInteger()), hex(v, "dsAx")));
        isTrue("SM9 user signing key dsA.y",
            Arrays.areEqual(f32(ds.getAffineYCoord().toBigInteger()), hex(v, "dsAy")));
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
            Arrays.areEqual(SM9Pairing.toBytes(g), hex(v, "g_GT")));

        Fp12 w = g.pow(new BigInteger((String)v.get("r"), 16));
        isTrue("SM9 pairing w = g^r", Arrays.areEqual(SM9Pairing.toBytes(w), hex(v, "w_GT")));
    }

    private byte[] g2(Map v, String xHi, String xLo, String yHi, String yLo)
    {
        return Arrays.concatenate(
            Arrays.concatenate(new byte[]{0x04}, hex(v, xHi), hex(v, xLo)),
            Arrays.concatenate(hex(v, yHi), hex(v, yLo)));
    }

    private static byte[] f32(BigInteger v)
    {
        return BigIntegers.asUnsignedByteArray(32, v);
    }

    public static void main(String[] args)
    {
        runTest(new SM9SignerTest());
    }
}
