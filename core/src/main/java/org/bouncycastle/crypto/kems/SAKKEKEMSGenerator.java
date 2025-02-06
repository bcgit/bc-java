package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SAKKEKEMSGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    public SAKKEKEMSGenerator(SecureRandom random)
    {
        this.random = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        SAKKEPublicKeyParameters keyParameters = (SAKKEPublicKeyParameters)recipientKey;
        ECPoint Z = keyParameters.getZ();
        BigInteger b = keyParameters.getIdentifier();
        BigInteger p = keyParameters.getPrime();
        BigInteger q = keyParameters.getQ();
        BigInteger g = keyParameters.getG();
        int n = keyParameters.getN();
        ECCurve curve = keyParameters.getCurve();
        ECPoint P = keyParameters.getP();

        // 1. Generate random SSV in range [0, 2^n - 1]
        BigInteger ssv = new BigInteger(n, random);


        // 2. Compute r = HashToIntegerRange(SSV || b, q)

        BigInteger r = SAKKEUtils.hashToIntegerRange(Arrays.concatenate(ssv.toByteArray(), b.toByteArray()), q);


        // 3. Compute R_(b,S) = [r]([b]P + Z_S)
        ECPoint bP = P.multiply(b).normalize();
        ECPoint R_bS = bP.add(Z).multiply(r).normalize();         // [r]([b]P + Z_S)

        // 4. Compute H = SSV XOR HashToIntegerRange( g^r, 2^n )
        BigInteger[] v = fp2Exponentiate(p, BigInteger.ONE, g, r, curve);
        BigInteger g_r = v[1].multiply(v[0].modInverse(p)).mod(p);

        BigInteger mask = SAKKEUtils.hashToIntegerRange(g_r.toByteArray(), BigInteger.ONE.shiftLeft(n)); // 2^n

        BigInteger H = ssv.xor(mask);
        //System.out.println(new String(Hex.encode(H.toByteArray())));
        // 5. Encode encapsulated data (R_bS, H)
        byte[] encapsulated = Arrays.concatenate(R_bS.getEncoded(false), H.toByteArray());

        return new SecretWithEncapsulationImpl(
            BigIntegers.asUnsignedByteArray(n / 8, ssv), // Output SSV as key material
            encapsulated
        );
    }


    public static BigInteger[] fp2Exponentiate(
        BigInteger p,
        BigInteger pointX,
        BigInteger pointY,
        BigInteger n,
        ECCurve curve)
    {
        BigInteger[] result = new BigInteger[2];

        // Initialize result with the original point
        BigInteger currentX = pointX;
        BigInteger currentY = pointY;
        ECPoint current = curve.createPoint(currentX, currentY);

        int numBits = n.bitLength();
        BigInteger[] rlt;
        // Process bits from MSB-1 down to 0
        for (int i = numBits - 2; i >= 0; i--)
        {
            // Square the current point
            rlt = SAKKEKEMExtractor.fp2PointSquare(currentX, currentY, p);
            current = current.timesPow2(2);
            currentX = rlt[0];
            currentY = rlt[1];
            // Multiply if bit is set
            if (n.testBit(i))
            {
                rlt = SAKKEKEMExtractor.fp2Multiply(currentX, currentY, pointX, pointY, p);

                currentX = rlt[0];
                currentY = rlt[1];
            }
        }

        result[0] = currentX;
        result[1] = currentY;
        return result;
    }
}
