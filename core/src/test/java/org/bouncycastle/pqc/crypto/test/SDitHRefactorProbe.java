package org.bouncycastle.pqc.crypto.test;

import java.security.MessageDigest;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sdith.SDitHKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sdith.SDitHParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHSigner;
import org.bouncycastle.util.encoders.Hex;

/**
 * Deterministic single-vector probe + profile loop for the SDitH performance
 * refactor. NOT a JUnit test; driven from a main() so it can be JFR-profiled
 * and A/B'd outside Gradle.
 *
 * Usage: SDitHRefactorProbe &lt;variant&gt; &lt;op&gt; [iters]
 *   variant: hc1g hc3g hc5g hc1p hc3p hc5p th1g th3g th5g th1p th3p th5p
 *            ("all" runs probe over every variant)
 *   op:      probe  -&gt; keygen+sign+verify, print SHA-256(pk|sk|sig) + verify
 *            sign   -&gt; timed sign loop (ms/iter)
 *            keygen -&gt; timed keygen loop (ms/iter)
 *            verify -&gt; timed verify loop (ms/iter)
 */
public class SDitHRefactorProbe
{
    // A fixed 48-byte NIST-DRBG seed (arbitrary but deterministic).
    private static final byte[] SEED = Hex.decode(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      + "202122232425262728292a2b2c2d2e2f");

    private static final byte[] MSG = Hex.decode(
        "2d2d2d20534469744820726566616374f72020707366206d7367207878787878");

    private static SDitHParameters params(String code)
    {
        if (code.equals("hc1g")) return SDitHParameters.sdith_hypercube_cat1_gf256;
        if (code.equals("hc3g")) return SDitHParameters.sdith_hypercube_cat3_gf256;
        if (code.equals("hc5g")) return SDitHParameters.sdith_hypercube_cat5_gf256;
        if (code.equals("hc1p")) return SDitHParameters.sdith_hypercube_cat1_p251;
        if (code.equals("hc3p")) return SDitHParameters.sdith_hypercube_cat3_p251;
        if (code.equals("hc5p")) return SDitHParameters.sdith_hypercube_cat5_p251;
        if (code.equals("th1g")) return SDitHParameters.sdith_threshold_cat1_gf256;
        if (code.equals("th3g")) return SDitHParameters.sdith_threshold_cat3_gf256;
        if (code.equals("th5g")) return SDitHParameters.sdith_threshold_cat5_gf256;
        if (code.equals("th1p")) return SDitHParameters.sdith_threshold_cat1_p251;
        if (code.equals("th3p")) return SDitHParameters.sdith_threshold_cat3_p251;
        if (code.equals("th5p")) return SDitHParameters.sdith_threshold_cat5_p251;
        throw new IllegalArgumentException("unknown variant " + code);
    }

    private static final String[] ALL = {
        "hc1g", "hc3g", "hc5g", "hc1p", "hc3p", "hc5p",
        "th1g", "th3g", "th5g", "th1p", "th3p", "th5p"
    };

    private static String sha(byte[] b)
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Hex.toHexString(md.digest(b));
    }

    private static AsymmetricCipherKeyPair keygen(SDitHParameters p)
    {
        SDitHKeyPairGenerator kpg = new SDitHKeyPairGenerator();
        kpg.init(new SDitHKeyGenerationParameters(new NISTSecureRandom(SEED, null), p));
        return kpg.generateKeyPair();
    }

    private static void probe(String code)
        throws Exception
    {
        SDitHParameters p = params(code);
        // Reproduce the KAT call shape: one random instance shared by keygen+sign.
        NISTSecureRandom rng = new NISTSecureRandom(SEED, null);
        SDitHKeyPairGenerator kpg = new SDitHKeyPairGenerator();
        kpg.init(new SDitHKeyGenerationParameters(rng, p));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        SDitHPublicKeyParameters pub = (SDitHPublicKeyParameters)kp.getPublic();
        SDitHPrivateKeyParameters priv = (SDitHPrivateKeyParameters)kp.getPrivate();
        byte[] pk = pub.getEncoded();
        byte[] sk = priv.getEncoded();

        SDitHSigner signer = new SDitHSigner();
        signer.init(true, new ParametersWithRandom(priv, rng));
        byte[] sig = signer.generateSignature(MSG);

        SDitHSigner verifier = new SDitHSigner();
        verifier.init(false, pub);
        boolean ok = verifier.verifySignature(MSG, sig);

        System.out.println(code
            + " pk(" + pk.length + ")=" + sha(pk)
            + " sk(" + sk.length + ")=" + sha(sk)
            + " sig(" + sig.length + ")=" + sha(sig)
            + " verify=" + ok);
    }

    private static double timeLoop(String code, String op, int iters)
    {
        SDitHParameters p = params(code);
        AsymmetricCipherKeyPair kp = keygen(p);
        SDitHPrivateKeyParameters priv = (SDitHPrivateKeyParameters)kp.getPrivate();
        SDitHPublicKeyParameters pub = (SDitHPublicKeyParameters)kp.getPublic();

        byte[] sigForVerify = null;
        if (op.equals("verify"))
        {
            SDitHSigner s = new SDitHSigner();
            s.init(true, new ParametersWithRandom(priv, new NISTSecureRandom(SEED, null)));
            sigForVerify = s.generateSignature(MSG);
        }

        // warm-up
        int warm = Math.max(3, iters / 10);
        for (int i = 0; i < warm; ++i)
        {
            runOp(op, p, priv, pub, sigForVerify);
        }

        long t0 = System.nanoTime();
        for (int i = 0; i < iters; ++i)
        {
            runOp(op, p, priv, pub, sigForVerify);
        }
        long t1 = System.nanoTime();
        return (t1 - t0) / 1e6 / iters;
    }

    private static long sink;

    private static void runOp(String op, SDitHParameters p,
                              SDitHPrivateKeyParameters priv, SDitHPublicKeyParameters pub,
                              byte[] sigForVerify)
    {
        if (op.equals("keygen"))
        {
            AsymmetricCipherKeyPair kp = keygen(p);
            sink += kp.getPublic().hashCode();
        }
        else if (op.equals("sign"))
        {
            SDitHSigner s = new SDitHSigner();
            s.init(true, new ParametersWithRandom(priv, new NISTSecureRandom(SEED, null)));
            byte[] sig = s.generateSignature(MSG);
            sink += sig.length;
        }
        else if (op.equals("verify"))
        {
            SDitHSigner v = new SDitHSigner();
            v.init(false, pub);
            if (v.verifySignature(MSG, sigForVerify))
            {
                sink += 1;
            }
        }
        else
        {
            throw new IllegalArgumentException("unknown op " + op);
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        String code = args.length > 0 ? args[0] : "hc1g";
        String op = args.length > 1 ? args[1] : "probe";
        int iters = args.length > 2 ? Integer.parseInt(args[2]) : 50;

        if (op.equals("probe"))
        {
            if (code.equals("all"))
            {
                for (int i = 0; i < ALL.length; ++i)
                {
                    probe(ALL[i]);
                }
            }
            else
            {
                probe(code);
            }
            return;
        }

        double ms = timeLoop(code, op, iters);
        System.out.println(code + " " + op + " " + iters + " iters: "
            + String.format("%.3f", ms) + " ms/iter   (sink=" + sink + ")");
    }
}
