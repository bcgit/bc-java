package org.bouncycastle.pqc.crypto.test;

public class FalconTest {
//	public static void main(String[] args) throws Exception {
//		FalconTest.testVectors();
//	}
//
//	public static void testVectors() throws Exception {
//		FalconParameters[] params = new FalconParameters[] {
//				FalconParameters.falcon512,
//				FalconParameters.falcon1024
//		};
//		String[] files = new String[] {
//			"falcon512-KAT.rsp",
//			"falcon1024-KAT.rsp"
//		};
//		for (int fileindex = 0; fileindex < files.length; fileindex++) {
//			String name = files[fileindex];
//			System.out.println("testing: " + name);
//			InputStream src = FalconTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/falcon/"+name);
//			BufferedReader bin = new BufferedReader(new InputStreamReader(src));
//			String line = null;
//			HashMap<String, String> buf = new HashMap<String, String>();
//            while ((line = bin.readLine()) != null)
//            {
//                line = line.trim();
//
//                if (line.startsWith("#"))
//                {
//                    continue;
//                }
//                if (line.length() == 0)
//                {
//                    if (buf.size() > 0)
//                    {
//                        String count = buf.get("count");
//                        System.out.println("test case: " + count);
//
//                        byte[] seed = Hex.decode(buf.get("seed")); // seed for Falcon secure random
//                        byte[] pk = Hex.decode(buf.get("pk"));     // public key
//                        byte[] sk = Hex.decode(buf.get("sk"));     // private key
//
//                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
//                        FalconParameters parameters = params[fileindex];
//
//                        FalconKeyPairGenerator kpGen = new FalconKeyPairGenerator();
//                        FalconKeyGenerationParameters genParam = new FalconKeyGenerationParameters(random, parameters);
//                        //
//                        // Generate keys and test.
//                        //
//                        kpGen.init(genParam);
//                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
//
//                        FalconPublicKeyParameters pubParams = (FalconPublicKeyParameters)kp.getPublic();
//                        FalconPrivateKeyParameters privParams = (FalconPrivateKeyParameters)kp.getPrivate();
//
////                        print_bytes(pk,"pk");
////                        print_bytes(pubParams.getPublicKey(),"pk");
////                        print_bytes(sk,"sk");
////                        print_bytes(privParams.getPrivateKey(),"sk");
//                        assert Arrays.areEqual(pk, pubParams.getPublicKey()) : "test " + count + " pk are not equal";
//                        assert Arrays.areEqual(sk, privParams.getPrivateKey()) : "test " + count + " sk are not equal";
//                    }
//                    buf.clear();
//
//                    continue;
//                }
//
//                int a = line.indexOf("=");
//                if (a > -1)
//                {
//                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
//                }
//
//
//            }
//            System.out.println("testing successful!");
//        }
//	}
//	private static void print_bytes(byte[] p, String name) {
//        System.out.print(name); System.out.print(" = ");
//        for (int i = 0; i < p.length; i++) {
//        	String resultWithPadZero = String.format("%2x", p[i])
//                    .replace(" ", "0");
//            System.out.print(resultWithPadZero);
//            if (i != p.length - 1) {
//                continue;
//            } else {
//                System.out.print("\n");
//            }
//        }
//    }
}
