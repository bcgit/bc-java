package org.bouncycastle.crypto.kems;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SAKKEPrivateKeyParameters;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import static org.bouncycastle.crypto.kems.SAKKEKEMSGenerator.pairing;

public class SAKKEKEMExtractor implements EncapsulatedSecretExtractor
{
    private final ECCurve curve;
    private final BigInteger p;
    private final BigInteger q;
    private final ECPoint P;
    private final ECPoint Z_S;
    private final ECPoint K_bS; // Receiver's RSK
    private final int n; // Security parameter
    private final SAKKEPrivateKeyParameters privateKey;

    public SAKKEKEMExtractor(SAKKEPrivateKeyParameters privateKey) {
        this.privateKey = privateKey;
        SAKKEPublicKeyParameters publicKey = privateKey.getPublicParams();
        this.curve = publicKey.getCurve();
        this.q = publicKey.getQ();
        this.P = publicKey.getP();
        this.p = publicKey.getp();
        this.Z_S = publicKey.getZ();
        this.K_bS = privateKey.getPrivatePoint();
        this.n = publicKey.getN();
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation) {
        try {
            // Step 1: Parse Encapsulated Data (R_bS, H)
            ECPoint R_bS = parseECPoint(encapsulation);
            BigInteger H = parseH(encapsulation);

            // Step 2: Compute w = <R_bS, K_bS> using pairing
            BigInteger w = computePairing(R_bS, K_bS);

            // Step 3: Compute SSV = H XOR HashToIntegerRange(w, 2^n)
            BigInteger ssv = computeSSV(H, w);

            // Step 4: Compute r = HashToIntegerRange(SSV || b)
//            BigInteger r = computeR(ssv, privateKey.getPrivatePoint());
//
//            // Step 5: Validate R_bS
//            if (!validateR_bS(r, privateKey.getPrivatePoint(), R_bS)) {
//                throw new IllegalStateException("Validation of R_bS failed");
//            }

            return BigIntegers.asUnsignedByteArray(n/8, ssv);
        } catch (Exception e) {
            throw new IllegalStateException("SAKKE extraction failed: " + e.getMessage());
        }
    }

    @Override
    public int getEncapsulationLength()
    {
        return 0;
    }

    private ECPoint parseECPoint(byte[] encapsulation) {
        int coordLen = (p.bitLength() + 7) / 8;
        byte[] xBytes = Arrays.copyOfRange(encapsulation, 0, coordLen);
        byte[] yBytes = Arrays.copyOfRange(encapsulation, coordLen, 2*coordLen);

        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        return curve.createPoint(x, y).normalize();
    }

    private BigInteger parseH(byte[] encapsulation) {
        int coordLen = (p.bitLength() + 7) / 8;
        byte[] hBytes = Arrays.copyOfRange(encapsulation, 2*coordLen, encapsulation.length);
        return new BigInteger(1, hBytes);
    }

    private BigInteger computePairing(ECPoint R, ECPoint K) {
        // Use your existing pairing implementation
        return pairing(R, K, p, q);
    }

    private BigInteger computeSSV(BigInteger H, BigInteger w) {
        BigInteger twoToN = BigInteger.ONE.shiftLeft(n);
        BigInteger mask = SAKKEUtils.hashToIntegerRange(w.toByteArray(), twoToN);
        return H.xor(mask);
    }

    private BigInteger computeR(BigInteger ssv, byte[] userId) {
        byte[] ssvBytes = BigIntegers.asUnsignedByteArray(ssv);
        byte[] ssvConcatB = Arrays.concatenate(ssvBytes, userId);
        return SAKKEUtils.hashToIntegerRange(ssvConcatB, q);
    }

    private boolean validateR_bS(BigInteger r, byte[] b, ECPoint receivedR) {
        try {
            // Compute [b]P
            ECPoint bP = P.multiply(new BigInteger(1, b)).normalize();

            // Compute [b]P + Z_S
            ECPoint bP_plus_Z = bP.add(Z_S).normalize();

            // Compute [r]([b]P + Z_S)
            ECPoint computedR = bP_plus_Z.multiply(r).normalize();

            return pointsEqual(computedR, receivedR);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean pointsEqual(ECPoint p1, ECPoint p2) {
        return p1.normalize().getXCoord().equals(p2.normalize().getXCoord())
            && p1.normalize().getYCoord().equals(p2.normalize().getYCoord());
    }
}
