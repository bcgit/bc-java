package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class SAKKEKEMSGenerator
    implements EncapsulatedSecretGenerator
{

    //    private static final BigInteger p = new BigInteger(Hex.decode("997ABB1F 0A563FDA 65C61198 DAD0657A\n" +
//        "               416C0CE1 9CB48261 BE9AE358 B3E01A2E\n" +
//        "               F40AAB27 E2FC0F1B 228730D5 31A59CB0\n" +
//        "               E791B39F F7C88A19 356D27F4 A666A6D0\n" +
//        "               E26C6487 326B4CD4 512AC5CD 65681CE1\n" +
//        "               B6AFF4A8 31852A82 A7CF3C52 1C3C09AA\n" +
//        "               9F94D6AF 56971F1F FCE3E823 89857DB0\n" +
//        "               80C5DF10 AC7ACE87 666D807A FEA85FEB"));
    private static final BigInteger p = new BigInteger(
        "997ABB1F0A563FDA65C61198DAD0657A416C0CE19CB48261BE9AE358B3E01A2E" +
            "F40AAB27E2FC0F1B228730D531A59CB0E791B39FF7C88A19356D27F4A666A6D0" +
            "E26C6487326B4CD4512AC5CD65681CE1B6AFF4A831852A82A7CF3C521C3C09AA" +
            "9F94D6AF56971F1FFCE3E82389857DB080C5DF10AC7ACE87666D807AFEA85FEB", 16
    );
    //    private static final BigInteger q = new BigInteger(Hex.decode("265EAEC7 C2958FF6 99718466 36B4195E\n" +
//        "               905B0338 672D2098 6FA6B8D6 2CF8068B\n" +
//        "               BD02AAC9 F8BF03C6 C8A1CC35 4C69672C\n" +
//        "               39E46CE7 FDF22286 4D5B49FD 2999A9B4\n" +
//        "               389B1921 CC9AD335 144AB173 595A0738\n" +
//        "               6DABFD2A 0C614AA0 A9F3CF14 870F026A\n" +
//        "               A7E535AB D5A5C7C7 FF38FA08 E2615F6C\n" +
//        "               203177C4 2B1EB3A1 D99B601E BFAA17FB"));
    private static final BigInteger q = new BigInteger(
        "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068B" +
            "BD02AAC9F8BF03C6C8A1CC354C69672C39E46CE7FDF222864D5B49FD2999A9B4" +
            "389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A" +
            "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB", 16
    );
//    private static final BigInteger a = BigInteger.valueOf(-3).mod(p); // y² = x³ - 3x
//    private static final BigInteger b = BigInteger.ZERO;
//    private static final ECCurve.Fp curve = new ECCurve.Fp(
//        p,                                   // Prime p
//        BigInteger.valueOf(-3).mod(p),             // a = -3
//        BigInteger.ZERO,                    // b = 0
//        q,                                  // Order of the subgroup (from RFC 6509)
//        BigInteger.ONE                      // Cofactor = 1
//    );

    // Base point P = (Px, Py)
    private static final BigInteger Px = new BigInteger(
        "53FC09EE332C29AD0A7990053ED9B52A2B1A2FD60AEC69C698B2F204B6FF7CBF" +
            "B5EDB6C0F6CE2308AB10DB9030B09E1043D5F22CDB9DFA55718BD9E7406CE890" +
            "9760AF765DD5BCCB337C86548B72F2E1A702C3397A60DE74A7C1514DBA66910D" +
            "D5CFB4CC80728D87EE9163A5B63F73EC80EC46C4967E0979880DC8ABEAE63895", 16
    );

    private static final BigInteger Py = new BigInteger(
        "0A8249063F6009F1F9F1F0533634A135D3E82016029906963D778D821E141178" +
            "F5EA69F4654EC2B9E7F7F5E5F0DE55F66B598CCF9A140B2E416CFF0CA9E032B9" +
            "70DAE117AD547C6CCAD696B5B7652FE0AC6F1E80164AA989492D979FC5A4D5F2" +
            "13515AD7E9CB99A980BDAD5AD5BB4636ADB9B5706A67DCDE75573FD71BEF16D7", 16
    );


    BigInteger g = new BigInteger(Hex.decode("66FC2A43 2B6EA392 148F1586 7D623068\n" +
        "               C6A87BD1 FB94C41E 27FABE65 8E015A87\n" +
        "               371E9474 4C96FEDA 449AE956 3F8BC446\n" +
        "               CBFDA85D 5D00EF57 7072DA8F 541721BE\n" +
        "               EE0FAED1 828EAB90 B99DFB01 38C78433\n" +
        "               55DF0460 B4A9FD74 B4F1A32B CAFA1FFA\n" +
        "               D682C033 A7942BCC E3720F20 B9B7B040\n" +
        "               3C8CAE87 B7A0042A CDE0FAB3 6461EA46"));
    private final int n = 128;
    private final SecureRandom random;

    public SAKKEKEMSGenerator(SecureRandom random)
    {
        this.random = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        // 1. Generate random SSV in range [0, 2^n - 1]
        BigInteger ssv = new BigInteger("123456789ABCDEF0123456789ABCDEF0", 16);//new BigInteger(n, random);

        // 2. Compute r = HashToIntegerRange(SSV || b, q)
        BigInteger b = new BigInteger("323031312D30320074656C3A2B34343737303039303031323300", 16); //getRecipientId((SAKKEPublicKey)recipientKey);
        BigInteger r = SAKKEUtils.hashToIntegerRange(Arrays.concatenate(ssv.toByteArray(), b.toByteArray()), q);
        System.out.println(new String(Hex.encode(r.toByteArray())));
        ECCurve.Fp curve = new ECCurve.Fp(
            p,                                   // Prime p
            BigInteger.valueOf(-3).mod(p),             // a = -3
            BigInteger.ZERO, // ,
            g,                                  // Order of the subgroup (from RFC 6509)
            BigInteger.ONE                      // Cofactor = 1
        );
        ECPoint P = curve.createPoint(Px, Py);
        ECPoint G = curve.createPoint(
            new BigInteger(Hex.decode("53FC09EE 332C29AD 0A799005 3ED9B52A\n" +
                "               2B1A2FD6 0AEC69C6 98B2F204 B6FF7CBF\n" +
                "               B5EDB6C0 F6CE2308 AB10DB90 30B09E10\n" +
                "               43D5F22C DB9DFA55 718BD9E7 406CE890\n" +
                "               9760AF76 5DD5BCCB 337C8654 8B72F2E1\n" +
                "               A702C339 7A60DE74 A7C1514D BA66910D\n" +
                "               D5CFB4CC 80728D87 EE9163A5 B63F73EC\n" +
                "               80EC46C4 967E0979 880DC8AB EAE63895")),  // Px
            new BigInteger(Hex.decode("0A824906 3F6009F1 F9F1F053 3634A135\n" +
                "               D3E82016 02990696 3D778D82 1E141178\n" +
                "               F5EA69F4 654EC2B9 E7F7F5E5 F0DE55F6\n" +
                "               6B598CCF 9A140B2E 416CFF0C A9E032B9\n" +
                "               70DAE117 AD547C6C CAD696B5 B7652FE0\n" +
                "               AC6F1E80 164AA989 492D979F C5A4D5F2\n" +
                "               13515AD7 E9CB99A9 80BDAD5A D5BB4636\n" +
                "               ADB9B570 6A67DCDE 75573FD7 1BEF16D7"))   // Py
        );
        ECPoint Z = curve.createPoint(
            new BigInteger("5958EF1B1679BF099B3A030DF255AA6A" +
                "23C1D8F143D4D23F753E69BD27A832F3" +
                "8CB4AD53DDEF4260B0FE8BB45C4C1FF5" +
                "10EFFE300367A37B61F701D914AEF097" +
                "24825FA0707D61A6DFF4FBD7273566CD" +
                "DE352A0B04B7C16A78309BE640697DE7" +
                "47613A5FC195E8B9F328852A579DB8F9" +
                "9B1D0034479EA9C5595F47C4B2F54FF2", 16),  // Px
            new BigInteger("1508D37514DCF7A8E143A6058C09A6BF" +
                "2C9858CA37C258065AE6BF7532BC8B5B" +
                "63383866E0753C5AC0E72709F8445F2E" +
                "6178E065857E0EDA10F68206B63505ED" +
                "87E534FB2831FF957FB7DC619DAE6130" +
                "1EEACC2FDA3680EA4999258A833CEA8F" +
                "C67C6D19487FB449059F26CC8AAB655A" +
                "B58B7CC796E24E9A394095754F5F8BAE", 16)   // Py
        );
        BigInteger z = new BigInteger("AFF429D35F84B110D094803B3595A6E2998BC99F", 16);
        // 3. Compute R_(b,S) = [r]([b]P + Z_S)
        ECPoint bP = P.multiply(b).normalize();
        ECPoint R_bS = bP.add(Z).multiply(r).normalize();         // [r]([b]P + Z_S)
        System.out.println("R_Bs x:" + new String(Hex.encode(R_bS.getXCoord().toBigInteger().toByteArray())));
        System.out.println("R_Bs y:" + new String(Hex.encode(R_bS.getYCoord().toBigInteger().toByteArray())));


        // 4. Compute H = SSV XOR HashToIntegerRange( g^r, 2^n )
        BigInteger[] result = fp2Exponentiate(p, BigInteger.ONE, g, r);
        BigInteger g_r = result[0].mod(p);
        g_r = g_r.modInverse(p);
        g_r = g_r.multiply(result[1]).mod(p);
        System.out.println("g_r " + new String(Hex.encode(g_r.toByteArray())));
        byte[] expected_g_r = Hex.decode("7D2A8438 E6291C64 9B6579EB 3B79EAE9\n" +
            "                 48B1DE9E 5F7D1F40 70A08F8D B6B3C515\n" +
            "                 6F2201AF FBB5CB9D 82AA3EC0 D0398B89\n" +
            "                 ABC78A13 A760C0BF 3F77E63D 0DF3F1A3\n" +
            "                 41A41B88 11DF197F D6CD0F00 3125606F\n" +
            "                 4F109F40 0F7292A1 0D255E3C 0EBCCB42\n" +
            "                 53FB182C 68F09CF6 CD9C4A53 DA6C74AD\n" +
            "                 007AF36B 8BCA979D 5895E282 F483FCD6");
        BigInteger mask = SAKKEUtils.hashToIntegerRange(g_r.toByteArray(), BigInteger.ONE.shiftLeft(n)); // 2^n
        System.out.println(new String(Hex.encode(mask.toByteArray())));

        BigInteger H = ssv.xor(mask);

        // 5. Encode encapsulated data (R_bS, H)
        byte[] encapsulated = Arrays.concatenate(R_bS.getEncoded(false), H.toByteArray());

        return new SecretWithEncapsulationImpl(
            encapsulated,
            BigIntegers.asUnsignedByteArray(n / 8, ssv) // Output SSV as key material
        );
    }


    // Helper method for F_p² exponentiation
    public static BigInteger[] fp2Exponentiate(
        BigInteger p,
        BigInteger x,
        BigInteger y,
        BigInteger exponent
    )
    {
        BigInteger[] result = new BigInteger[2];
        sakkePointExponent(p, result, x, y, exponent);
        return result;
    }

    public static boolean sakkePointExponent(
        BigInteger p,
        BigInteger[] result,
        BigInteger pointX,
        BigInteger pointY,
        BigInteger n
    )
    {
        if (n.equals(BigInteger.ZERO))
        {
            return false;
        }

        // Initialize result with the original point
        BigInteger currentX = pointX;
        BigInteger currentY = pointY;

        int numBits = n.bitLength();

        // Process bits from MSB-1 down to 0
        for (int i = numBits - 2; i >= 0; i--)
        {
            // Square the current point
            //sakkePointSquare(p, new BigInteger[]{currentX, currentY});
            // Compute newX = (x + y)(x - y) mod p
            BigInteger xPlusY = currentX.add(currentY).mod(p);
            BigInteger xMinusY = currentX.subtract(currentY).mod(p);
            BigInteger newX = xPlusY.multiply(xMinusY).mod(p);

            // Compute newY = 2xy mod p
            BigInteger newY = currentX.multiply(currentY).multiply(BigInteger.valueOf(2)).mod(p);
            currentX = newX;
            currentY = newY;
            // Multiply if bit is set
            if (n.testBit(i))
            {
                //sakkePointsMultiply(p, currentX, currentY, pointX, pointY);
                BigInteger real = currentX.multiply(pointX)
                    .subtract(currentY.multiply(pointY))
                    .mod(p);

                // Compute imaginary part = x1*y2 + x2*y1 mod p
                BigInteger imag = currentX.multiply(pointY)
                    .add(pointX.multiply(currentY))
                    .mod(p);

                currentX = real;
                currentY = imag;
            }
        }

        result[0] = currentX;
        result[1] = currentY;
        return true;
    }


    private BigInteger getRecipientId(SAKKEPublicKeyParameters pubKey)
    {
        byte[] hashedId = SAKKEUtils.hash(pubKey.getZ().getEncoded(false));  // Hash Z_S
        return new BigInteger(1, hashedId).mod(pubKey.getQ().subtract(BigInteger.ONE)).add(BigIntegers.TWO);
    }

    public static class FP2Element
    {
        private final BigInteger a; // Real part
        private final BigInteger b; // Imaginary part
        private final BigInteger p; // Prime modulus

        public FP2Element(BigInteger a, BigInteger b, BigInteger p)
        {
            this.a = a.mod(p);
            this.b = b.mod(p);
            this.p = p;
        }

        public FP2Element add(FP2Element other)
        {
            return new FP2Element(a.add(other.a), b.add(other.b), p);
        }

        public FP2Element subtract(FP2Element other)
        {
            return new FP2Element(a.subtract(other.a), b.subtract(other.b), p);
        }

        public FP2Element multiply(FP2Element other)
        {
            BigInteger real = a.multiply(other.a).subtract(b.multiply(other.b)).mod(p);
            BigInteger imag = a.multiply(other.b).add(b.multiply(other.a)).mod(p);
            return new FP2Element(real, imag, p);
        }

        public FP2Element inverse()
        {
            BigInteger denom = a.pow(2).add(b.pow(2)).mod(p);
            BigInteger invDenom = denom.modInverse(p);
            return new FP2Element(a.multiply(invDenom), b.negate().multiply(invDenom), p);
        }

        public FP2Element square()
        {
            return this.multiply(this);
        }

        public FP2Element pow(BigInteger exponent)
        {
            // Implement exponentiation using square-and-multiply
            FP2Element result = new FP2Element(BigInteger.ONE, BigInteger.ZERO, p);
            FP2Element base = this;
            for (int i = exponent.bitLength() - 1; i >= 0; i--)
            {
                result = result.square();
                if (exponent.testBit(i))
                {
                    result = result.multiply(base);
                }
            }
            return result;
        }

        // Getters
        public BigInteger getA()
        {
            return a;
        }

        public BigInteger getB()
        {
            return b;
        }
    }

    /**
     * Computes the Tate-Lichtenbaum pairing ⟨P, Q⟩ as per RFC 6508.
     * <p>
     * //* @param P First point (on E(F_p)).
     *
     * @param Q Second point (on E(F_p)).
     * @return Result of the pairing in the field F_p^2.
     */
    public static BigInteger pairing(ECPoint R, ECPoint Q, BigInteger p, BigInteger q)
    {
        ECCurve curve = R.getCurve();
        //FP2Element v = new FP2Element(BigInteger.ONE, BigInteger.ZERO, p); // Initialize to 1+0i

        // Use correct exponent from RFC 6508: (p+1)/q
        BigInteger exponent = p.add(BigInteger.ONE).divide(q);

        String qBits = q.subtract(BigInteger.ONE).toString(2);
        ECPoint C = R.normalize();
        BigInteger vx = BigInteger.ONE;
        BigInteger vy = BigInteger.ZERO;

        // Evaluate line at Q using F_p² arithmetic
        BigInteger Qx = Q.getAffineXCoord().toBigInteger();
        BigInteger Qy = Q.getAffineYCoord().toBigInteger();

        ECPoint Rnorm = R.normalize();
        BigInteger Rx = Rnorm.getAffineXCoord().toBigInteger();
        BigInteger Ry = Rnorm.getAffineYCoord().toBigInteger();
        int n = q.subtract(BigInteger.ONE).bitLength() - 1;
        for (int j = n; j > 0; j--)
        {
            /*
            *             BigInteger xPlusY = currentX.add(currentY).mod(p);
            BigInteger xMinusY = currentX.subtract(currentY).mod(p);
            BigInteger newX = xPlusY.multiply(xMinusY).mod(p);

            // Compute newY = 2xy mod p
            BigInteger newY = currentX.multiply(currentY).multiply(BigInteger.valueOf(2)).mod(p);
            * */
            BigInteger xPlusY = vx.add(vy).mod(p);
            BigInteger xMinusY = vx.subtract(vy).mod(p);
            BigInteger newX = xPlusY.multiply(xMinusY).mod(p);

            // Compute newY = 2xy mod p
            BigInteger newY = vx.multiply(vy).multiply(BigInteger.valueOf(2)).mod(p);
            vx = newX;
            vy = newY;

            C = C.normalize();
            BigInteger Cx = C.getAffineXCoord().toBigInteger();
            BigInteger Cy = C.getAffineYCoord().toBigInteger();


            // Line function for doubling
            //3*(C_x^2 - 1)
            BigInteger t_x1_bn = (Cx.multiply(Cx).mod(p).subtract(BigInteger.ONE)).multiply(BigInteger.valueOf(3));
            //Qx + Cx
            BigInteger t_bn = Qx.add(Cx);
            //3*(C_x^2 - 1)(Qx+Cx)
            t_x1_bn = t_x1_bn.multiply(t_bn).mod(p);
            //Cy^2*2
            t_bn = Cy.multiply(Cy).mod(p).multiply(BigInteger.valueOf(2));
            //3*(C_x^2 - 1)(Qx+Cx) - Cy^2*2
            t_x1_bn = t_x1_bn.subtract(t_bn).mod(p);
            // Cy*2*Qy
            BigInteger t_x2_bn = Cy.multiply(BigInteger.valueOf(2)).multiply(Qy).mod(p);

            /*
            *                 BigInteger real = currentX.multiply(pointX)
                    .subtract(currentY.multiply(pointY))
                    .mod(p);

                // Compute imaginary part = x1*y2 + x2*y1 mod p
                BigInteger imag = currentX.multiply(pointY)
                    .add(pointX.multiply(currentY))
                    .mod(p);*/
            BigInteger real = vx.multiply(t_x1_bn)
                .subtract(vy.multiply(t_x2_bn))
                .mod(p);

            // Compute imaginary part = x1*y2 + x2*y1 mod p
            BigInteger imag = vx.multiply(t_x2_bn)
                .add(t_x1_bn.multiply(vy))
                .mod(p);

            vx = real;
            vy = imag;

            C = C.twice().normalize();

            if (qBits.charAt(j) == '1')
            {
                t_x1_bn = Qx.add(Rx).multiply(Cy).mod(p);
                BigInteger tmp_t_bn = Qx.add(Cx).multiply(Ry);
                t_x1_bn = t_x1_bn.subtract(tmp_t_bn).mod(p);
                t_x2_bn = Cx.subtract(Rx).multiply(Qy).mod(p);
                real = vx.multiply(t_x1_bn)
                    .subtract(vy.multiply(t_x2_bn))
                    .mod(p);

                // Compute imaginary part = x1*y2 + x2*y1 mod p
                imag = vx.multiply(t_x2_bn)
                    .add(t_x1_bn.multiply(vy))
                    .mod(p);

                vx = real;
                vy = imag;
                C = C.add(Rnorm).normalize();
            }
        }
        BigInteger xPlusY = vx.add(vy).mod(p);
        BigInteger xMinusY = vx.subtract(vy).mod(p);
        BigInteger newX = xPlusY.multiply(xMinusY).mod(p);

        // Compute newY = 2xy mod p
        BigInteger newY = vx.multiply(vy).multiply(BigInteger.valueOf(2)).mod(p);
        vx = newX;
        vy = newY;

        xPlusY = vx.add(vy).mod(p);
        xMinusY = vx.subtract(vy).mod(p);
        newX = xPlusY.multiply(xMinusY).mod(p);

        // Compute newY = 2xy mod p
        newY = vx.multiply(vy).multiply(BigInteger.valueOf(2)).mod(p);

        vx = newX;
        vy = newY;

        BigInteger w = vx.modInverse(p).multiply(vy).mod(p);

        return w;
//        // Final exponentiation
//        FP2Element t = v.pow(exponent);
//
//        // Convert to F_p representative: b/a mod p
//        BigInteger a = t.getA();
//        BigInteger b = t.getB();
//        return b.multiply(a.modInverse(p)).mod(p);
    }
//    public static BigInteger pairing(ECPoint R, ECPoint Q, BigInteger p, BigInteger q) {
//        ECCurve curve = R.getCurve();
//        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
//        int N = qMinus1.bitLength() - 1;
//
//        // Initialize V = (1, 0) in Fp²
//        BigInteger vx = BigInteger.ONE;
//        BigInteger vy = BigInteger.ZERO;
//
//        // Initialize C = R
//        ECPoint C = R.normalize();
//        BigInteger Cx = C.getAffineXCoord().toBigInteger();
//        BigInteger Cy = C.getAffineYCoord().toBigInteger();
//
//        // Precompute Q coordinates
//        ECPoint Qnorm = Q.normalize();
//        BigInteger Qx = Qnorm.getAffineXCoord().toBigInteger();
//        BigInteger Qy = Qnorm.getAffineYCoord().toBigInteger();
//
//        // Precompute R coordinates for addition steps
//        ECPoint Rnorm = R.normalize();
//        BigInteger Rx = Rnorm.getAffineXCoord().toBigInteger();
//        BigInteger Ry = Rnorm.getAffineYCoord().toBigInteger();
//
//        for (; N > 0; N--) {
//            // V = V² (complex squaring)
//            BigInteger[] squared = pointSquare(vx, vy, p);
//            vx = squared[0];
//            vy = squared[1];
//
//            // Calculate line function for doubling
//            BigInteger[] T = computeLineFunction(Cx, Cy, Qx, Qy, p);
//
//            // V = V * T (complex multiplication)
//            BigInteger[] multiplied = pointMultiply(vx, vy, T[0], T[1], p);
//            vx = multiplied[0];
//            vy = multiplied[1];
//
//            // Double point C
//            BigInteger[] doubled = pointDouble(Cx, Cy, p);
//            Cx = doubled[0];
//            Cy = doubled[1];
//
//            if (qMinus1.testBit(N-1)) {
//                // Calculate line function for addition
//                BigInteger[] TAdd = computeLineFunctionAdd(Cx, Cy, Rx, Ry, Qx, Qy, p);
//
//                // V = V * TAdd
//                multiplied = pointMultiply(vx, vy, TAdd[0], TAdd[1], p);
//                vx = multiplied[0];
//                vy = multiplied[1];
//
//                // Add points C = C + R
//                BigInteger[] added = pointAdd(Cx, Cy, Rx, Ry, p);
//                Cx = added[0];
//                Cy = added[1];
//            }
//        }
//
//        // Final squaring V = V²
//        BigInteger[] squared = pointSquare(vx, vy, p);
//        vx = squared[0];
//        vy = squared[1];
//        squared = pointSquare(vx, vy, p);
//        vx = squared[0];
//        vy = squared[1];
//
//        // Compute w = (Vy * Vx⁻¹) mod p
//        BigInteger vxInv = vx.modInverse(p);
//        return vy.multiply(vxInv).mod(p);
//    }
//
//    // Helper methods implementing exact C code operations
//    private static BigInteger[] pointSquare(BigInteger x, BigInteger y, BigInteger p) {
//        BigInteger xPlusY = x.add(y).mod(p);
//        BigInteger xMinusY = x.subtract(y).mod(p);
//        return new BigInteger[] {
//            xPlusY.multiply(xMinusY).mod(p),
//            x.multiply(y).multiply(BigInteger.valueOf(2)).mod(p)
//        };
//    }
//
//    private static BigInteger[] pointMultiply(BigInteger a, BigInteger b, BigInteger c, BigInteger d, BigInteger p) {
//        return new BigInteger[] {
//            a.multiply(d).add(b.multiply(c)).mod(p),
//            a.multiply(c).subtract(b.multiply(d)).mod(p),
//
//        };
//    }
//
//    private static BigInteger[] pointDouble(BigInteger x, BigInteger y, BigInteger p) {
//        BigInteger slope = x.pow(2).multiply(BigInteger.valueOf(3))
//            .mod(p)
//            .multiply(y.multiply(BigInteger.valueOf(2)).modInverse(p))
//            .mod(p);
//        return new BigInteger[] {
//            slope.pow(2).subtract(x.multiply(BigInteger.valueOf(2))).mod(p),
//            slope.multiply(x.subtract(slope.pow(2).mod(p)))
//                .subtract(y).mod(p)
//        };
//    }
//
//    private static BigInteger[] pointAdd(BigInteger x1, BigInteger y1, BigInteger x2, BigInteger y2, BigInteger p) {
//        BigInteger slope = y2.subtract(y1)
//            .multiply(x2.subtract(x1).modInverse(p))
//            .mod(p);
//        return new BigInteger[] {
//            slope.pow(2).subtract(x1).subtract(x2).mod(p),
//            slope.multiply(x1.subtract(slope.pow(2).subtract(x1).subtract(x2).mod(p)))
//                .subtract(y1).mod(p)
//        };
//    }
//
//    private static BigInteger[] computeLineFunction(BigInteger Cx, BigInteger Cy,
//                                                    BigInteger Qx, BigInteger Qy,
//                                                    BigInteger p) {
//        // Calculate 3*(Cx² - 1)
//        BigInteger t_x1 = Cx.pow(2).subtract(BigInteger.ONE).multiply(BigInteger.valueOf(3)).mod(p);
//        // Calculate Qx + Cx
//        BigInteger t = Qx.add(Cx).mod(p);
//        // Multiply components
//        t_x1 = t_x1.multiply(t).mod(p);
//        // Subtract 2*Cy²
//        t_x1 = t_x1.subtract(Cy.pow(2).multiply(BigInteger.valueOf(2))).mod(p);
//        // Calculate 2*Cy*Qy
//        BigInteger t_x2 = Cy.multiply(BigInteger.valueOf(2)).multiply(Qy).mod(p);
//        return new BigInteger[] {t_x1, t_x2};
//    }
//
//    private static BigInteger[] computeLineFunctionAdd(BigInteger Cx, BigInteger Cy,
//                                                       BigInteger Rx, BigInteger Ry,
//                                                       BigInteger Qx, BigInteger Qy,
//                                                       BigInteger p) {
//        // Calculate (Cy - Ry)
//        BigInteger numerator = Cy.subtract(Ry).mod(p);
//        // Calculate (Cx - Rx)⁻¹
//        BigInteger denominator = Cx.subtract(Rx).modInverse(p);
//        BigInteger slope = numerator.multiply(denominator).mod(p);
//
//        // Calculate line function components
//        BigInteger t_x1 = slope.multiply(Qx.add(Cx).mod(p)).mod(p);
//        BigInteger t_x2 = slope.multiply(Qy).negate().mod(p);
//        return new BigInteger[] {t_x1, t_x2};
//    }


}
