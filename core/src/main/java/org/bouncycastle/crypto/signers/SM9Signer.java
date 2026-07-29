package org.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * The SM9 identity-based digital signature algorithm (GM/T 0044.2-2016).
 * <p>
 * For signing, initialise with an {@link SM9SigPrivateKeyParameters} (optionally
 * wrapped in {@link ParametersWithRandom}). For verifying, initialise with an
 * {@link SM9SigMasterPublicKeyParameters} wrapped in a {@link ParametersWithID}
 * carrying the signer's identity.
 * <p>
 * The produced signature is encoded as h (32 bytes, big-endian) followed by the
 * uncompressed encoding of the G1 point S (0x04 || x || y).
 */
public class SM9Signer
    implements Signer
{
    private final DSAKCalculator kCalculator = new RandomDSAKCalculator();
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private boolean forSigning;
    private SM9SigPrivateKeyParameters signKey;
    private SM9SigMasterPublicKeyParameters verifyKey;
    private byte[] identity;
    private Fp12 g;   // cached e(P1, P_pub-s)

    public void init(boolean forSigning, CipherParameters param)
    {
        this.forSigning = forSigning;
        this.identity = null;

        CipherParameters base = param;
        if (base instanceof ParametersWithID)
        {
            identity = ((ParametersWithID)base).getID();
            base = ((ParametersWithID)base).getParameters();
        }

        if (forSigning)
        {
            SecureRandom random = null;
            if (base instanceof ParametersWithRandom)
            {
                random = ((ParametersWithRandom)base).getRandom();
                base = ((ParametersWithRandom)base).getParameters();
            }

            signKey = (SM9SigPrivateKeyParameters)base;
            verifyKey = signKey.getMasterPublicKey();
            kCalculator.init(SM9Curve.N, CryptoServicesRegistrar.getSecureRandom(random));
        }
        else
        {
            verifyKey = (SM9SigMasterPublicKeyParameters)base;
            if (identity == null)
            {
                throw new IllegalArgumentException("SM9 verification requires the signer identity (ParametersWithID)");
            }
        }

        g = SM9Pairing.pairing(SM9Curve.P1, verifyKey.getPointG2());
        buffer.reset();
    }

    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] in, int off, int len)
    {
        buffer.write(in, off, len);
    }

    public byte[] generateSignature()
        throws CryptoException
    {
        if (!forSigning)
        {
            throw new IllegalStateException("SM9Signer not initialised for signing");
        }

        byte[] m = buffer.toByteArray();
        buffer.reset();

        BigInteger n = SM9Curve.N;
        BigInteger h;
        BigInteger l;
        do
        {
            BigInteger r = kCalculator.nextK();          // A2: r in [1, N-1]
            Fp12 w = g.powSecure(r);                     // A3: w = g^r (r is the secret nonce)
            h = SM9Sm3.h2(Arrays.concatenate(m, SM9Pairing.toBytes(w)), n);  // A4
            l = r.subtract(h).mod(n);                    // A5: l = (r - h) mod N
        }
        while (l.signum() == 0);

        ECPoint s = SM9Curve.multiplySecure(signKey.getPrivatePoint(), l).normalize();   // A6: S = [l]ds
        return encodeSignature(h, s);
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning)
        {
            throw new IllegalStateException("SM9Signer not initialised for verification");
        }

        byte[] m = buffer.toByteArray();
        buffer.reset();

        try
        {
            BigInteger n = SM9Curve.N;
            BigInteger h = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));   // B1
            if (h.compareTo(ECConstants.ONE) < 0 || h.compareTo(n.subtract(ECConstants.ONE)) > 0)
            {
                return false;
            }

            ECPoint s = SM9Curve.G1.decodePoint(Arrays.copyOfRange(signature, 32, signature.length));  // B2
            if (s.isInfinity() || !s.isValid())
            {
                return false;
            }

            Fp12 t = g.pow(h);                                                        // B4: t = g^h
            BigInteger h1 = SM9Sm3.h1(Arrays.append(identity, SM9SigMasterPrivateKeyParameters.HID), n);  // B5
            SM9G2Point p = SM9Curve.P2.multiply(h1).add(verifyKey.getPointG2());      // B6: P = [h1]P2 + P_pub-s
            Fp12 u = SM9Pairing.pairing(s, p);                                        // B7: u = e(S, P)
            Fp12 w = u.multiply(t);                                                   // B8: w' = u * t
            BigInteger h2 = SM9Sm3.h2(Arrays.concatenate(m, SM9Pairing.toBytes(w)), n);  // B9
            return h2.equals(h);
        }
        catch (Exception e)
        {
            return false;
        }
    }

    public void reset()
    {
        buffer.reset();
    }

    private static byte[] encodeSignature(BigInteger h, ECPoint s)
    {
        return Arrays.concatenate(BigIntegers.asUnsignedByteArray(32, h), s.getEncoded(false));
    }
}
