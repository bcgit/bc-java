package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.agreement.SM9KeyExchange;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Known-answer test for the SM9 key exchange protocol (GM/T 0044.3-2016)
 * against the GM/T 0044.5-2016 Annex B vector (crypto/sm9/sm9_keyexchange.txt):
 * both parties' ephemeral values, the shared key and the key-confirmation tags
 * S_A / S_B are reproduced byte-for-byte.
 */
public class SM9KeyExchangeTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9KeyExchange";
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
        Map v = loadVectors("sm9_keyexchange.txt");
        BigInteger ke = new BigInteger((String)v.get("ke"), 16);
        byte[] idA = hex(v, "IDA");
        byte[] idB = hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));
        byte hid = SM9EncMasterPrivateKeyParameters.HID_EXCHANGE;

        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(ke);
        SM9EncPrivateKeyParameters deA = master.generateUserKey(idA, hid);
        SM9EncPrivateKeyParameters deB = master.generateUserKey(idB, hid);

        SM9KeyExchange a = new SM9KeyExchange(deA, idB, true);
        SM9KeyExchange b = new SM9KeyExchange(deB, idA, false);
        ECPoint ra = a.generateEphemeral(new TestRandomBigInteger(256, hex(v, "rA")));
        ECPoint rb = b.generateEphemeral(new TestRandomBigInteger(256, hex(v, "rB")));

        isTrue("SM9 key exchange RA", Arrays.areEqual(xCoord(ra), hex(v, "RA_x")));
        isTrue("SM9 key exchange RB", Arrays.areEqual(xCoord(rb), hex(v, "RB_x")));

        byte[] skA = a.calculateKey(klen, rb);
        byte[] skB = b.calculateKey(klen, ra);
        isTrue("SM9 key exchange SKA", Arrays.areEqual(skA, hex(v, "SK")));
        isTrue("SM9 key exchange SKB", Arrays.areEqual(skB, hex(v, "SK")));

        isTrue("SM9 key exchange S_B", Arrays.areEqual(b.getResponderConfirmation(), hex(v, "S_B")));
        isTrue("SM9 key exchange S_B (initiator agrees)", Arrays.areEqual(a.getResponderConfirmation(), hex(v, "S_B")));
        isTrue("SM9 key exchange S_A", Arrays.areEqual(a.getInitiatorConfirmation(), hex(v, "S_A")));
        isTrue("SM9 key exchange S_A (responder agrees)", Arrays.areEqual(b.getInitiatorConfirmation(), hex(v, "S_A")));

        // a non-positive key length must be rejected: the KDF would produce no
        // output (matching the SM9KEMGenerator / SM9KEMExtractor guards)
        try
        {
            a.calculateKey(0, rb);
            fail("SM9KeyExchange accepted klenBits = 0");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("klenBits must be positive".equals(e.getMessage()));
        }
    }

    private static byte[] xCoord(ECPoint p)
    {
        return BigIntegers.asUnsignedByteArray(32, p.normalize().getAffineXCoord().toBigInteger());
    }

    public static void main(String[] args)
    {
        runTest(new SM9KeyExchangeTest());
    }
}
