package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.MalformedPacketException;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketInputStream;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.LibrePGPPreferredEncryptionModes;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SignatureSubpacketsTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "SignatureSubpacketsTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testLibrePGPPreferredEncryptionModesSubpacket();
        testTruncatedSubpacketsRejected();
    }

    private void testLibrePGPPreferredEncryptionModesSubpacket()
            throws IOException
    {
        int[] algorithms = new int[] {AEADAlgorithmTags.EAX, AEADAlgorithmTags.OCB};
        LibrePGPPreferredEncryptionModes encModes = new LibrePGPPreferredEncryptionModes(
                false, algorithms);

        isTrue("Encryption Modes encoding mismatch",
                Arrays.areEqual(algorithms, encModes.getPreferences()));
        isFalse("Mismatch in critical flag", encModes.isCritical());

        // encode to byte array and check correctness
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        encModes.encode(bOut);

        isEncodingEqual("Packet encoding mismatch", new byte[]{
                3, // length
                SignatureSubpacketTags.LIBREPGP_PREFERRED_ENCRYPTION_MODES,
                AEADAlgorithmTags.EAX,
                AEADAlgorithmTags.OCB
        }, bOut.toByteArray());
    }

    /**
     * The Features, TrustSignature, SignatureTarget, RevocationKey, RevocationReason and
     * NotationData subpackets index their body from an accessor (e.g.
     * {@link Features#getFeatures()} reads {@code data[0]}, {@link NotationData#getNotationName()}
     * copies {@code nameLength} octets from offset 8, where {@code nameLength} comes from the
     * subpacket's own header). A truncated body must therefore be rejected when the subpacket
     * is parsed, with an {@link IllegalArgumentException}, rather than decoding cleanly and
     * throwing an {@link ArrayIndexOutOfBoundsException} later when an accessor is read. This
     * matches the existing IssuerFingerprint / IntendedRecipientFingerprint guards.
     */
    private void testTruncatedSubpacketsRejected()
            throws IOException
    {
        // getFeatures() / supportsFeature() read data[0]
        isConstructionRejected("Features", new byte[0]);

        // getDepth() reads data[0], getTrustAmount() reads data[1]
        isConstructionRejected("TrustSignature", new byte[0]);
        isConstructionRejected("TrustSignature", new byte[1]);

        // getPublicKeyAlgorithm() reads data[0], getHashAlgorithm() reads data[1]
        isConstructionRejected("SignatureTarget", new byte[0]);
        isConstructionRejected("SignatureTarget", new byte[1]);

        // getSignatureClass() reads data[0], getAlgorithm() reads data[1]
        isConstructionRejected("RevocationKey", new byte[0]);
        isConstructionRejected("RevocationKey", new byte[1]);

        // getRevocationReason() reads data[0]
        isConstructionRejected("RevocationReason", new byte[0]);

        // NotationData: header is flags[4] || nameLength[2] || valueLength[2] (8 octets);
        // getNotationName() copies nameLength octets from offset 8 and getNotationValueBytes()
        // copies valueLength octets from offset 8 + nameLength, so a body whose header declares
        // more name/value data than it carries must be rejected, not decoded and later AIOOBE'd.
        isConstructionRejected("NotationData", new byte[0]);                    // shorter than the 8-octet header
        isConstructionRejected("NotationData", notationBody(4, 0, new byte[0])); // declares 4 name octets, none supplied
        isConstructionRejected("NotationData", notationBody(0, 4, new byte[0])); // declares 4 value octets, none supplied
        isConstructionRejected("NotationData", notationBody(2, 2, new byte[]{'a', 'b', 'c'})); // one value octet short

        // a body exactly at the minimum length must still be accepted, with working accessors
        testMinimalBodiesAccepted();

        // the truncated body is reachable from the wire, not just the API: a subpacket whose
        // length field is 1 carries only its type octet (an empty body), which the parser now
        // rejects with a MalformedPacketException wrapping the constructor's exception.
        isWireDecodeRejected(SignatureSubpacketTags.FEATURES, 1);
        isWireDecodeRejected(SignatureSubpacketTags.TRUST_SIG, 2);
        isWireDecodeRejected(SignatureSubpacketTags.NOTATION_DATA, notationBody(4, 0, new byte[0]));
    }

    private void isConstructionRejected(String name, byte[] body)
    {
        try
        {
            construct(name, body);
            fail(name + " accepted a truncated " + body.length + "-octet body");
        }
        catch (IllegalArgumentException e)
        {
            // expected - the parse constructor rejects a body too short for its accessors
        }
    }

    private SignatureSubpacket construct(String name, byte[] body)
    {
        if (name.equals("Features"))
        {
            return new Features(false, false, body);
        }
        if (name.equals("TrustSignature"))
        {
            return new TrustSignature(false, false, body);
        }
        if (name.equals("SignatureTarget"))
        {
            return new SignatureTarget(false, false, body);
        }
        if (name.equals("RevocationKey"))
        {
            return new RevocationKey(false, false, body);
        }
        if (name.equals("RevocationReason"))
        {
            return new RevocationReason(false, false, body);
        }
        if (name.equals("NotationData"))
        {
            return new NotationData(false, false, body);
        }
        throw new IllegalStateException("unknown subpacket: " + name);
    }

    private static byte[] notationBody(int nameLength, int valueLength, byte[] payload)
    {
        // flags[4] || nameLength[2] || valueLength[2] || payload
        byte[] body = new byte[8 + payload.length];
        body[4] = (byte)(nameLength >>> 8);
        body[5] = (byte)nameLength;
        body[6] = (byte)(valueLength >>> 8);
        body[7] = (byte)valueLength;
        System.arraycopy(payload, 0, body, 8, payload.length);
        return body;
    }

    private void testMinimalBodiesAccepted()
    {
        Features features = new Features(false, false, new byte[]{Features.FEATURE_SEIPD_V2});
        isTrue("Features body not preserved", features.getFeatures() == Features.FEATURE_SEIPD_V2);
        isTrue("Features.supportsFeature mismatch", features.supportsFeature(Features.FEATURE_SEIPD_V2));

        TrustSignature trust = new TrustSignature(false, false, new byte[]{2, (byte)120});
        isTrue("TrustSignature depth mismatch", trust.getDepth() == 2);
        isTrue("TrustSignature trust-amount mismatch", trust.getTrustAmount() == 120);

        SignatureTarget target = new SignatureTarget(false, false, new byte[]{1, 8});
        isTrue("SignatureTarget public-key-algorithm mismatch", target.getPublicKeyAlgorithm() == 1);
        isTrue("SignatureTarget hash-algorithm mismatch", target.getHashAlgorithm() == 8);
        isTrue("SignatureTarget hash-data should be empty", target.getHashData().length == 0);

        RevocationKey revocationKey = new RevocationKey(false, false, new byte[]{(byte)0x80, 1});
        isTrue("RevocationKey signature-class mismatch", revocationKey.getSignatureClass() == (byte)0x80);
        isTrue("RevocationKey algorithm mismatch", revocationKey.getAlgorithm() == 1);
        isTrue("RevocationKey fingerprint should be empty", revocationKey.getFingerprint().length == 0);

        RevocationReason revocationReason = new RevocationReason(false, false, new byte[]{3});
        isTrue("RevocationReason code mismatch", revocationReason.getRevocationReason() == 3);
        isTrue("RevocationReason description should be empty", revocationReason.getRevocationDescription().equals(""));

        NotationData notationData = new NotationData(false, false, notationBody(2, 2, new byte[]{'a', 'b', 'c', 'd'}));
        isTrue("NotationData name mismatch", notationData.getNotationName().equals("ab"));
        isTrue("NotationData value mismatch", notationData.getNotationValue().equals("cd"));
    }

    private void isWireDecodeRejected(int type, int subpacketLength)
            throws IOException
    {
        // a length-field-only body, all octets zero, too short for the subpacket's accessors
        isWireDecodeRejected(type, new byte[subpacketLength - 1]);
    }

    private void isWireDecodeRejected(int type, byte[] body)
            throws IOException
    {
        // OpenPGP signature subpacket framing: a one-octet length field (< 192) covering the
        // type octet plus body, the type octet, then the body octets (too short for the
        // subpacket's accessors).
        byte[] encoded = new byte[2 + body.length];
        encoded[0] = (byte)(1 + body.length);
        encoded[1] = (byte)type;
        System.arraycopy(body, 0, encoded, 2, body.length);

        SignatureSubpacketInputStream sIn = new SignatureSubpacketInputStream(
                new ByteArrayInputStream(encoded));
        try
        {
            sIn.readPacket();
            fail("Wire decode accepted a truncated subpacket of type " + type);
        }
        catch (MalformedPacketException e)
        {
            // expected - the constructor's IllegalArgumentException surfaced at decode time
        }
    }

    public static void main(String[] args)
    {
        runTest(new SignatureSubpacketsTest());
    }
}
