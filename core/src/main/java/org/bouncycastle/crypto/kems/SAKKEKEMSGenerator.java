package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SAKKEPublicKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
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
        // 3. Compute R_(b,S) = [r]([b]P + Z_S)
        ECPoint bP = P.multiply(b).normalize();
        ECPoint Z_S = Z;// P.multiply(ssv).normalize();;//.multiply(new BigInteger("AFF429D35F84B110D094803B3595A6E2998BC99F", 16));          // Z_S
        ECPoint R_bS = bP.add(Z_S).multiply(r);         // [r]([b]P + Z_S)
        System.out.println("R_Bs x:" + new String(Hex.encode(R_bS.getXCoord().toBigInteger().toByteArray())));
        System.out.println("R_Bs y:" + new String(Hex.encode(R_bS.getYCoord().toBigInteger().toByteArray())));


        // 4. Compute H = SSV XOR HashToIntegerRange( g^r, 2^n )
        BigInteger g_r = pairing(R_bS, G, p, q);
        BigInteger mask = SAKKEUtils.hashToIntegerRange(g_r.toByteArray(), BigInteger.ONE.shiftLeft(n)); // 2^n

        BigInteger H = ssv.xor(mask);

        // 5. Encode encapsulated data (R_bS, H)
        byte[] encapsulated = encodeData(R_bS, H);

        return new SecretWithEncapsulationImpl(
            BigIntegers.asUnsignedByteArray(n / 8, ssv), // Output SSV as key material
            encapsulated
        );
    }

    private BigInteger getRecipientId(SAKKEPublicKey pubKey)
    {
        byte[] hashedId = SAKKEUtils.hash(pubKey.getZ().getEncoded(false));  // Hash Z_S
        return new BigInteger(1, hashedId).mod(pubKey.getQ().subtract(BigInteger.ONE)).add(BigIntegers.TWO);
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
        ECFieldElement i = curve.fromBigInteger(BigInteger.ONE.negate()); // i = -1 in F_p^2

        ECPoint C = R;
        BigInteger c = p.add(BigInteger.ONE).divide(q);
        ECFieldElement v = curve.fromBigInteger(BigInteger.ONE); // v = 1 in F_p

        String qBits = q.subtract(BigInteger.ONE).toString(2); // Binary representation of q-1

        for (int j = 1; j < qBits.length(); j++)
        { // Skip MSB
            // l = (3 * (C_x^2 - 1)) / (2 * C_y)
            ECFieldElement Cx = C.getAffineXCoord();
            ECFieldElement Cy = C.getAffineYCoord();
            ECFieldElement l = Cx.square().multiply(curve.fromBigInteger(ECFieldElement.THREE)).subtract(curve.fromBigInteger(BigInteger.ONE))
                .divide(Cy.multiply(curve.fromBigInteger(BigIntegers.TWO)));

            // v = v^2 * (l * (Q_x + C_x) + (i * Q_y - C_y))
            ECFieldElement Qx = Q.getAffineXCoord();
            ECFieldElement Qy = Q.getAffineYCoord();
            v = v.square().multiply(l.multiply(Qx.add(Cx)).add(i.multiply(Qy).subtract(Cy)));

            // Double the point
            C = C.twice();

            // If the bit is 1, perform additional step
            if (qBits.charAt(j) == '1')
            {
                // l = (C_y - R_y) / (C_x - R_x)
                ECFieldElement Rx = R.getAffineXCoord();
                ECFieldElement Ry = R.getAffineYCoord();
                l = Cy.subtract(Ry).divide(Cx.subtract(Rx));

                // v = v * (l * (Q_x + C_x) + (i * Q_y - C_y))
                v = v.multiply(l.multiply(Qx.add(Cx)).add(i.multiply(Qy).subtract(Cy)));

                // C = C + R
                C = C.add(R);
            }
        }

        // Compute v^c
        v = curve.fromBigInteger(v.toBigInteger().pow(c.intValue()));

        // Convert to F_p representative
        return computeFpRepresentative(v, curve);
    }

    private static BigInteger computeFpRepresentative(ECFieldElement t, ECCurve curve)
    {
        // Characteristic of F_p
        BigInteger p = ((ECCurve.Fp)curve).getQ();

        // Assume t = a + i * b in F_p² → extract a, b
        ECFieldElement a = t; // In F_p², a is the real part
        ECFieldElement b = t.multiply(curve.fromBigInteger(BigInteger.ONE.negate())); // Imaginary part

        // Compute b/a mod p
        return b.toBigInteger().multiply(a.toBigInteger().modInverse(p)).mod(p);
    }

    public static byte[] encodeData(ECPoint R_bS, BigInteger H)
    {
        // 1. Serialize EC Point (use compressed format for efficiency)
        byte[] R_bS_bytes = R_bS.getEncoded(true);

        // 2. Serialize H (convert to a fixed-length byte array)
        byte[] H_bytes = H.toByteArray();

        // 3. Combine both into a single byte array
        ByteBuffer buffer = ByteBuffer.allocate(R_bS_bytes.length + H_bytes.length);
        buffer.put(R_bS_bytes);
        buffer.put(H_bytes);

        return buffer.array();
    }
}
