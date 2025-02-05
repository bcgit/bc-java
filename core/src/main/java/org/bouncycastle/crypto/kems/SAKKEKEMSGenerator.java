package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SAKKEKEMSGenerator
    implements EncapsulatedSecretGenerator
{

    private static final BigInteger p = new BigInteger(
        "997ABB1F0A563FDA65C61198DAD0657A416C0CE19CB48261BE9AE358B3E01A2E" +
            "F40AAB27E2FC0F1B228730D531A59CB0E791B39FF7C88A19356D27F4A666A6D0" +
            "E26C6487326B4CD4512AC5CD65681CE1B6AFF4A831852A82A7CF3C521C3C09AA" +
            "9F94D6AF56971F1FFCE3E82389857DB080C5DF10AC7ACE87666D807AFEA85FEB", 16
    );

    private static final BigInteger q = new BigInteger(
        "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068B" +
            "BD02AAC9F8BF03C6C8A1CC354C69672C39E46CE7FDF222864D5B49FD2999A9B4" +
            "389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A" +
            "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB", 16
    );

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
    private static final int n = 128;
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
        //System.out.println(new String(Hex.encode(r.toByteArray())));
        ECCurve.Fp curve = new ECCurve.Fp(
            p,                                   // Prime p
            BigInteger.valueOf(-3).mod(p),             // a = -3
            BigInteger.ZERO, // ,
            g,                                  // Order of the subgroup (from RFC 6509)
            BigInteger.ONE                      // Cofactor = 1
        );
        ECPoint P = curve.createPoint(Px, Py);

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

        // 3. Compute R_(b,S) = [r]([b]P + Z_S)
        ECPoint bP = P.multiply(b).normalize();
        ECPoint R_bS = bP.add(Z).multiply(r).normalize();         // [r]([b]P + Z_S)
//        System.out.println("R_Bs x:" + new String(Hex.encode(R_bS.getXCoord().toBigInteger().toByteArray())));
//        System.out.println("R_Bs y:" + new String(Hex.encode(R_bS.getYCoord().toBigInteger().toByteArray())));


        // 4. Compute H = SSV XOR HashToIntegerRange( g^r, 2^n )
        BigInteger[] v = fp2Exponentiate(p, BigInteger.ONE, g, r, curve);
        BigInteger g_r = v[1].multiply(v[0].modInverse(p)).mod(p);

        BigInteger mask = SAKKEUtils.hashToIntegerRange(g_r.toByteArray(), BigInteger.ONE.shiftLeft(n)); // 2^n
        //System.out.println(new String(Hex.encode(mask.toByteArray())));

        BigInteger H = ssv.xor(mask);
        //System.out.println(new String(Hex.encode(H.toByteArray())));
        // 5. Encode encapsulated data (R_bS, H)
        byte[] encapsulated = Arrays.concatenate(R_bS.getEncoded(false), H.toByteArray());

        return new SecretWithEncapsulationImpl(
            BigIntegers.asUnsignedByteArray(n / 8, ssv), // Output SSV as key material
            encapsulated
        );
    }


    // Helper method for F_p² exponentiation
    public static BigInteger[] fp2Exponentiate(
        BigInteger p,
        BigInteger x,
        BigInteger y,
        BigInteger exponent,
        ECCurve.Fp curve
    )
    {
        BigInteger[] result = new BigInteger[2];
        sakkePointExponent(p, result, x, y, exponent, curve);
        return result;
    }

    public static boolean sakkePointExponent(
        BigInteger p,
        BigInteger[] result,
        BigInteger pointX,
        BigInteger pointY,
        BigInteger n,
        ECCurve.Fp curve)
    {

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
        return true;
    }
}
