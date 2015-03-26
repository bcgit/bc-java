//package org.bouncycastle.math.ec.test;
//
//import java.math.BigInteger;
//import java.util.Random;
//
//import junit.framework.TestCase;
//
//import org.bouncycastle.asn1.sec.SECNamedCurves;
//import org.bouncycastle.asn1.x9.X9ECParameters;
//import org.bouncycastle.math.ec.ECCurve;
//import org.bouncycastle.math.ec.ECPoint;
//import org.bouncycastle.math.ec.NafL2RMultiplier;
//import org.bouncycastle.math.ec.ReferenceMultiplier;
//import org.bouncycastle.math.ec.WNafL2RMultiplier;
//import org.bouncycastle.math.ec.WTauNafMultiplier;
//
//public class TnafTest extends TestCase
//{
//    private Random m_rand = new Random();
//
//    private String ecPointToString(ECPoint p) {
//        StringBuffer sb = new StringBuffer("x = ");
//        sb.append(p.getX().toBigInteger().toString());
//        sb.append("; y = ");
//        sb.append(p.getY().toBigInteger().toString());
//        return sb.toString();
//    }
//
//    private ECPoint repeatedMultiply(ECPoint p, BigInteger k)
//    {
//        ECPoint result = p.multiply(k);
//        for (int i = 1; i < 10; ++i)
//        {
//            ECPoint check = p.multiply(k);
//            assertEquals(result, check);
//        }
//        return result;
//    }
//
//    private void implTestMultiplyTnaf(String curveName) {
//        X9ECParameters x9ECParameters = SECNamedCurves.getByName(curveName);
//
//        ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m)x9ECParameters.getCurve();
//        BigInteger n = curve.getN();
//
//        // The generator is multiplied by random b to get random q
//        BigInteger b = new BigInteger(n.bitLength(), m_rand);
//        ECPoint g = x9ECParameters.getG();
//        ECPoint.F2m p = (ECPoint.F2m)g.multiply(b);
//
//        BigInteger k = new BigInteger(n.bitLength(), m_rand);
//        long now1 = System.currentTimeMillis();
//        p.setECMultiplier(new WTauNafMultiplier());
//        ECPoint refRWTnaf = repeatedMultiply(p, k);
//        long now2 = System.currentTimeMillis();
//        p.setECMultiplier(new WNafL2RMultiplier());
//        ECPoint refWnaf = repeatedMultiply(p, k);
//        long now3 = System.currentTimeMillis();
//        p.setECMultiplier(new NafL2RMultiplier());
//        ECPoint refFpNaf = repeatedMultiply(p, k);
//        long now4 = System.currentTimeMillis();
//        p.setECMultiplier(new ReferenceMultiplier());
//        ECPoint reference = repeatedMultiply(p, k);
//        long now5 = System.currentTimeMillis();
//
//        assertEquals("WTNAF multiplication is incorrect", refRWTnaf, reference);
//        assertEquals("FPNAF multiplication is incorrect", refFpNaf, reference);
//        assertEquals("WNAF multiplication is incorrect", refWnaf, reference);
//
//        System.out.println(curveName + ": Multiply WTNAF took millis:  " + (now2 - now1));
//        System.out.println(curveName + ": Multiply WNAF took millis:   " + (now3 - now2));
//        System.out.println(curveName + ": Multiply FPNAF took millis:  " + (now4 - now3));
//        System.out.println(curveName + ": Multiply REFE took millis:   " + (now5 - now4));
//
////        System.out.println(curveName + ": refRWTnaf  = " + ecPointToString(refRWTnaf));
////        System.out.println(curveName + ": refWnaf    = " + ecPointToString(refWnaf));
////        System.out.println(curveName + ": refFpNaf   = " + ecPointToString(refFpNaf));
////        System.out.println(curveName + ": reference  = " + ecPointToString(reference) + "\n");
//        System.out.println();
//    }
//
//    public void testMultiplyTnaf() {
//        System.out.println("\n\n\n*****  Start test multiplications on F2m (Koblitz) *****");
//        implTestMultiplyTnaf("sect163k1");
//        implTestMultiplyTnaf("sect233k1");
//        implTestMultiplyTnaf("sect239k1");
//        implTestMultiplyTnaf("sect283k1");
//        implTestMultiplyTnaf("sect409k1");
//        implTestMultiplyTnaf("sect571k1");
//    }
//
//    private void implTestMultiplyWnaf(String curveName) {
//        X9ECParameters x9ECParameters = SECNamedCurves.getByName(curveName);
//
//        BigInteger r = x9ECParameters.getN();
//
//        // The generator is multiplied by random b to get random q
//        BigInteger b = new BigInteger(r.bitLength(), m_rand);
//        ECPoint g = x9ECParameters.getG();
//        ECPoint p = g.multiply(b);
//
//        BigInteger k = new BigInteger(r.bitLength(), m_rand);
//        long now1 = System.currentTimeMillis();
//        p.setECMultiplier(new WNafL2RMultiplier());
//        ECPoint refWnaf = repeatedMultiply(p, k);
//        long now2 = System.currentTimeMillis();
//        p.setECMultiplier(new NafL2RMultiplier());
//        ECPoint refFpNaf = repeatedMultiply(p, k);
//        long now3 = System.currentTimeMillis();
//        p.setECMultiplier(new ReferenceMultiplier());
//        ECPoint reference = repeatedMultiply(p, k);
//        long now4 = System.currentTimeMillis();
//
//        assertEquals("WNAF multiplication is incorrect", refWnaf, reference);
//        assertEquals("FPNAF multiplication is incorrect", refFpNaf, reference);
//
//        System.out.println(curveName + ": Multiply WNAF took millis:   " + (now2 - now1));
//        System.out.println(curveName + ": Multiply FPNAF took millis:  " + (now3 - now2));
//        System.out.println(curveName + ": Multiply REFE took millis:   " + (now4 - now3));
//
////        System.out.println(curveName + ": refWnaf    = " + ecPointToString(refWnaf));
////        System.out.println(curveName + ": refFpNaf   = " + ecPointToString(refFpNaf));
////        System.out.println(curveName + ": reference  = " + ecPointToString(reference));
//        System.out.println();
//    }
//
//    public void testMultiplyWnaf() {
//        System.out.println("\n\n\n*****  Start test multiplications on F2m *****");
//        implTestMultiplyWnaf("sect113r1");
//        implTestMultiplyWnaf("sect113r2");
//        implTestMultiplyWnaf("sect131r1");
//        implTestMultiplyWnaf("sect131r2");
//        implTestMultiplyWnaf("sect163r1");
//        implTestMultiplyWnaf("sect163r2");
//        implTestMultiplyWnaf("sect193r1");
//        implTestMultiplyWnaf("sect193r2");
//        implTestMultiplyWnaf("sect233r1");
//        implTestMultiplyWnaf("sect283r1");
//        implTestMultiplyWnaf("sect409r1");
//        implTestMultiplyWnaf("sect571r1");
//
//        System.out.println("\n\n\n*****  Start test multiplications on Fp  *****");
//        implTestMultiplyWnaf("secp112r1");
//        implTestMultiplyWnaf("secp128r1");
//        implTestMultiplyWnaf("secp160r1");
//        implTestMultiplyWnaf("secp192r1");
//        implTestMultiplyWnaf("secp224r1");
//        implTestMultiplyWnaf("secp256r1");
//        implTestMultiplyWnaf("secp384r1");
//        implTestMultiplyWnaf("secp521r1");
//    }
//}
