package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.agreement.SM9KeyExchange;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncUserKeyParametersGenerator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Known-answer test for the SM9 key exchange protocol (GM/T 0044.3-2016)
 * against both official GM/T 0044.5-2016 Annex B vectors - the Chinese
 * edition's example (hid = 0x02, crypto/sm9/sm9_keyexchange.txt) and the
 * official English edition's example (hid = 0x03,
 * crypto/sm9/sm9_keyexchange_hid03.txt); the hid is the KGC's published
 * choice, taken from the vector file. For each, both parties' ephemeral
 * values, the shared key and the key-confirmation tags S_A / S_B are
 * reproduced byte-for-byte.
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
        checkVector("sm9_keyexchange.txt");
        checkVector("sm9_keyexchange_hid03.txt");
        checkHidValidation();
    }

    private void checkVector(String fileName)
        throws Exception
    {
        Map v = loadVectors(fileName);
        BigInteger ke = new BigInteger((String)v.get("ke"), 16);
        byte[] identityA = hex(v, "IDA");
        byte[] identityB = hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));
        byte hid = (byte)Integer.parseInt((String)v.get("hid"), 16);

        // derive named exchange keys under the hid the vector's KGC published
        // (0x02 in the Chinese-edition example, 0x03 in the English-edition one)
        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(ke);
        SM9EncPrivateKeyParameters deA = master.generateExchangeKey(identityA, hid);
        SM9EncPrivateKeyParameters deB = master.generateExchangeKey(identityB, hid);
        isTrue(fileName + " deA records its hid", deA.getHid() == hid);
        isTrue(fileName + " deA is an exchange key", deA.isExchangeKey());

        SM9KeyExchange a = new SM9KeyExchange(deA, identityB, true);
        SM9KeyExchange b = new SM9KeyExchange(deB, identityA, false);
        ECPoint ra = a.generateEphemeral(new TestRandomBigInteger(256, hex(v, "rA")));
        ECPoint rb = b.generateEphemeral(new TestRandomBigInteger(256, hex(v, "rB")));

        isTrue(fileName + " RA", Arrays.areEqual(xCoord(ra), hex(v, "RA_x")));
        isTrue(fileName + " RB", Arrays.areEqual(xCoord(rb), hex(v, "RB_x")));

        byte[] skA = a.calculateKey(klen, rb);
        byte[] skB = b.calculateKey(klen, ra);
        isTrue(fileName + " SKA", Arrays.areEqual(skA, hex(v, "SK")));
        isTrue(fileName + " SKB", Arrays.areEqual(skB, hex(v, "SK")));

        isTrue(fileName + " S_B", Arrays.areEqual(b.getResponderConfirmation(), hex(v, "S_B")));
        isTrue(fileName + " S_B (initiator agrees)", Arrays.areEqual(a.getResponderConfirmation(), hex(v, "S_B")));
        isTrue(fileName + " S_A", Arrays.areEqual(a.getInitiatorConfirmation(), hex(v, "S_A")));
        isTrue(fileName + " S_A (responder agrees)", Arrays.areEqual(b.getInitiatorConfirmation(), hex(v, "S_A")));

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

    private void checkHidValidation()
        throws Exception
    {
        SM9EncMasterPrivateKeyParameters master =
            new SM9EncMasterPrivateKeyParameters(BigInteger.valueOf(0x1234));
        byte[] identity = "Alice".getBytes("US-ASCII");
        byte[] badHids = new byte[]{ (byte)0x00, (byte)0x01, (byte)0x04, (byte)0xFF };
        for (int i = 0; i != badHids.length; i++)
        {
            try
            {
                master.generateUserKey(identity, badHids[i]);
                fail("generateUserKey accepted hid 0x" + Integer.toHexString(badHids[i] & 0xFF));
            }
            catch (IllegalArgumentException e)
            {
                isTrue("hid must be HID (0x03) or HID_EXCHANGE (0x02)".equals(e.getMessage()));
            }
            try
            {
                master.generateExchangeKey(identity, badHids[i]);
                fail("generateExchangeKey accepted hid 0x" + Integer.toHexString(badHids[i] & 0xFF));
            }
            catch (IllegalArgumentException e)
            {
                isTrue("hid must be HID (0x03) or HID_EXCHANGE (0x02)".equals(e.getMessage()));
            }
        }
        // the published identifier values pass (through the interface for the KEM side)
        SM9EncUserKeyParametersGenerator kgc = master;
        isTrue(kgc.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID) != null);
        isTrue(kgc.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE) != null);
        isTrue(master.generateExchangeKey(identity).getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);

        // KEM/decryption keys and exchange keys are mutually rejected by the consumers:
        // an exchange key pairs de with a peer-supplied point, so one key serving both
        // would hand any exchange peer a pairing oracle on de
        SM9EncPrivateKeyParameters encKey = master.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);
        try
        {
            new SM9KeyExchange(encKey, "Bob".getBytes("US-ASCII"), true);
            fail("SM9KeyExchange accepted a KEM/decryption user key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 key exchange requires a key-exchange user key from generateExchangeKey".equals(e.getMessage()));
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
