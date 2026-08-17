package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.agreement.SM9KeyExchange;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncUserKeyParametersGenerator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Known-answer test for the SM9 key exchange protocol (GM/T 0044.3-2016)
 * against both official GM/T 0044.5-2016 Annex B vectors - the Chinese
 * edition's example (hid = 0x02, crypto/sm9/sm9_keyexchange.txt) and the
 * official English edition's example (hid = 0x03,
 * crypto/sm9/sm9_keyexchange_hid03.txt); the hid is the KGC's published
 * choice, taken from the vector file. For each, the master public key, both
 * KGC-derived user keys, both parties' ephemeral values, the shared key and the
 * key-confirmation tags S_A / S_B are reproduced byte-for-byte - with party A
 * running on a key rebuilt through fromEncodedExchangeKey, the import path for
 * a party holding its KGC-served key but not the master private key.
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

        // the master public key and both KGC-derived user keys the standard prints
        isTrue(fileName + " master public key Ppub-e", Arrays.areEqual(
            master.getPublicKeyParameters().getEncoded(),
            Arrays.concatenate(new byte[]{0x04}, hex(v, "Ppube_x"), hex(v, "Ppube_y"))));
        isTrue(fileName + " user key deA", Arrays.areEqual(
            deA.getPrivatePoint().getEncoded(), g2(v, "deA_x_hi", "deA_x_lo", "deA_y_hi", "deA_y_lo")));
        isTrue(fileName + " user key deB", Arrays.areEqual(
            deB.getPrivatePoint().getEncoded(), g2(v, "deB_x_hi", "deB_x_lo", "deB_y_hi", "deB_y_lo")));

        // party A runs on a key rebuilt from its point encoding - the import path a
        // party served by the KGC uses, no master private key involved - and must
        // reproduce the exchange byte-for-byte
        SM9EncPrivateKeyParameters deAImported = SM9EncPrivateKeyParameters.fromEncodedExchangeKey(
            deA.getEncoded(), master.getPublicKeyParameters(), identityA, hid);
        isTrue(fileName + " imported deA is an exchange key", deAImported.isExchangeKey());
        isTrue(fileName + " imported deA records its hid", deAImported.getHid() == hid);

        SM9KeyExchange a = new SM9KeyExchange(deAImported, identityB, true);
        SM9KeyExchange b = new SM9KeyExchange(deB, identityA, false);
        ECPoint ra = a.generateEphemeral(new TestRandomBigInteger(256, hex(v, "rA")));
        ECPoint rb = b.generateEphemeral(new TestRandomBigInteger(256, hex(v, "rB")));

        isTrue(fileName + " RA", Arrays.areEqual(SM9Curve.g1ToBytes(ra),
            Arrays.concatenate(hex(v, "RA_x"), hex(v, "RA_y"))));
        isTrue(fileName + " RB", Arrays.areEqual(SM9Curve.g1ToBytes(rb),
            Arrays.concatenate(hex(v, "RB_x"), hex(v, "RB_y"))));

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

        // an exchange key rebuilt from its encoding carries the exchange usage,
        // defaults to the published exchange hid, and is rejected by the KEM side
        // exactly like a KGC-derived one
        SM9EncPrivateKeyParameters exchKey = master.generateExchangeKey(identity);
        SM9EncPrivateKeyParameters imported = SM9EncPrivateKeyParameters.fromEncodedExchangeKey(
            exchKey.getEncoded(), master.getPublicKeyParameters(), identity);
        isTrue("imported exchange key claims the exchange usage", imported.isExchangeKey());
        isTrue("imported exchange key defaults to HID_EXCHANGE",
            imported.getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
        try
        {
            new SM9KEMExtractor(imported, 128);
            fail("SM9KEMExtractor accepted an imported key-exchange user key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 KEM decapsulation requires an encryption user key, not a key-exchange key".equals(e.getMessage()));
        }
        // and the import validates the hid the same way the derivation does
        try
        {
            SM9EncPrivateKeyParameters.fromEncodedExchangeKey(
                exchKey.getEncoded(), master.getPublicKeyParameters(), identity, (byte)0x04);
            fail("fromEncodedExchangeKey accepted hid 0x04");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("hid must be HID (0x03) or HID_EXCHANGE (0x02)".equals(e.getMessage()));
        }
    }

    private byte[] g2(Map v, String xHi, String xLo, String yHi, String yLo)
    {
        return Arrays.concatenate(
            Arrays.concatenate(new byte[]{0x04}, hex(v, xHi), hex(v, xLo)),
            Arrays.concatenate(hex(v, yHi), hex(v, yLo)));
    }

    public static void main(String[] args)
    {
        runTest(new SM9KeyExchangeTest());
    }
}
