package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9SignMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SignPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SM9Signer;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
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
        byte[] id = hex(v, "IDA");
        byte[] msg = hex(v, "M");

        SM9SignMasterPrivateKeyParameters master = new SM9SignMasterPrivateKeyParameters(ks);
        SM9SignPrivateKeyParameters userKey = master.generateUserKey(id);

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
        verifier.init(false, new ParametersWithID(master.getPublicKeyParameters(), id));
        verifier.update(msg, 0, msg.length);
        isTrue("SM9 signature verify", verifier.verifySignature(sig));

        SM9Signer tampered = new SM9Signer();
        tampered.init(false, new ParametersWithID(master.getPublicKeyParameters(), id));
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
        emptyVerifier.init(false, new ParametersWithID(master.getPublicKeyParameters(), id));
        isTrue("SM9 zero-length message verifies", emptyVerifier.verifySignature(emptySig));

        SM9Signer emptyWrong = new SM9Signer();
        emptyWrong.init(false, new ParametersWithID(master.getPublicKeyParameters(), id));
        emptyWrong.update((byte)0x00);
        isTrue("SM9 zero-length signature does not verify a non-empty message",
            !emptyWrong.verifySignature(emptySig));
    }

    public static void main(String[] args)
    {
        runTest(new SM9SignerTest());
    }
}
