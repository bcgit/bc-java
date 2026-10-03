package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.MalformedPacketException;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketInputStream;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.LibrePGPPreferredEncryptionModes;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
        testLibrePGPPreferredEncryptionModesLookup();
        testTruncatedSubpacketsRejected();
        testFixedLengthSubpacketsRejected();
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
     * {@link PGPSignatureSubpacketVector#getPreferredLibrePgpEncryptionModes()} reads the LibrePGP
     * Preferred Encryption Modes subpacket (type 34). It used to look up the RFC 9580 Preferred AEAD
     * Ciphersuites subpacket (type 39) and cast it to the LibrePGP class, so a signature carrying
     * only type 34 gave null and a signature carrying type 39 threw a ClassCastException. By
     * default the OpenPGP API puts type 39 on the direct-key signature of every key it generates.
     */
    private void testLibrePGPPreferredEncryptionModesLookup()
            throws IOException
    {
        int[] modes = new int[] {AEADAlgorithmTags.EAX, AEADAlgorithmTags.OCB};
        PGPSignatureSubpacketGenerator gen = new PGPSignatureSubpacketGenerator();
        gen.setPreferredLibrePgpEncryptionModes(false, modes);
        PGPSignatureSubpacketVector libreOnly = gen.generate();
        isTrue("LibrePGP encryption modes mismatch",
                Arrays.areEqual(modes, libreOnly.getPreferredLibrePgpEncryptionModes()));
        isTrue("decoded LibrePGP encryption modes mismatch",
                Arrays.areEqual(modes, reparse(libreOnly).getPreferredLibrePgpEncryptionModes()));

        gen = new PGPSignatureSubpacketGenerator();
        gen.setPreferredAEADCiphersuites(PreferredAEADCiphersuites.builder(false)
                .addCombination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB));
        PGPSignatureSubpacketVector aeadOnly = gen.generate();
        isNotNull("AEAD ciphersuites missing", aeadOnly.getPreferredAEADCiphersuites());
        isNull("AEAD ciphersuites reported as LibrePGP encryption modes",
                aeadOnly.getPreferredLibrePgpEncryptionModes());
        isNull("decoded AEAD ciphersuites reported as LibrePGP encryption modes",
                reparse(aeadOnly).getPreferredLibrePgpEncryptionModes());

        gen.setPreferredLibrePgpEncryptionModes(false, modes);
        PGPSignatureSubpacketVector both = gen.generate();
        isTrue("LibrePGP encryption modes mismatch with AEAD ciphersuites present",
                Arrays.areEqual(modes, both.getPreferredLibrePgpEncryptionModes()));
        PGPSignatureSubpacketVector decoded = reparse(both);
        isTrue("decoded LibrePGP encryption modes mismatch with AEAD ciphersuites present",
                Arrays.areEqual(modes, decoded.getPreferredLibrePgpEncryptionModes()));
        isTrue("decoded AEAD ciphersuites mismatch", decoded.getPreferredAEADCiphersuites().isSupported(
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB)));

        // type 34 held as a plain PreferredAlgorithms, which addCustomSubpacket() and fromSubpackets() accept
        PGPSignatureSubpacketVector generic = PGPSignatureSubpacketVector.fromSubpackets(new SignatureSubpacket[]{
                new PreferredAlgorithms(SignatureSubpacketTags.LIBREPGP_PREFERRED_ENCRYPTION_MODES, false, modes)});
        isTrue("generic LibrePGP encryption modes mismatch",
                Arrays.areEqual(modes, generic.getPreferredLibrePgpEncryptionModes()));
    }

    private PGPSignatureSubpacketVector reparse(PGPSignatureSubpacketVector vector)
            throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        SignatureSubpacket[] packets = vector.toArray();
        for (int i = 0; i != packets.length; i++)
        {
            packets[i].encode(bOut);
        }

        SignatureSubpacketInputStream sIn = new SignatureSubpacketInputStream(
                new ByteArrayInputStream(bOut.toByteArray()));
        List<SignatureSubpacket> decoded = new ArrayList<SignatureSubpacket>();
        SignatureSubpacket p;
        while ((p = sIn.readPacket()) != null)
        {
            decoded.add(p);
        }
        return PGPSignatureSubpacketVector.fromSubpackets(decoded);
    }

    /**
     * The Features, TrustSignature, SignatureTarget, RevocationKey and RevocationReason
     * subpackets index a fixed offset of their body from an accessor (e.g.
     * {@link Features#getFeatures()} reads {@code data[0]}). A truncated body (empty, or a
     * single octet for the two-octet subpackets) must therefore be rejected when the subpacket
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

        // getNotationName()/getNotationValueBytes() index the 8-octet header (flags[4],
        // nameLength[2], valueLength[2]) then the name and value, so a body shorter than
        // 8 + nameLength + valueLength must be rejected. The guard previously counted only a
        // 4-octet header, so a body that declared more name/value than it carried slipped past
        // and overran later in an accessor (github #2346).
        isConstructionRejected("NotationData", new byte[0]);            // shorter than the 8-octet header
        isConstructionRejected("NotationData", new byte[7]);            // still shorter than the header
        isConstructionRejected("NotationData", notationBody(2, 2, 0));  // header declares 4 body octets, none present
        isConstructionRejected("NotationData", notationBody(1, 0, 0));  // header declares a 1-octet name, none present

        // a body exactly at the minimum length must still be accepted, with working accessors
        testMinimalBodiesAccepted();

        // the truncated body is reachable from the wire, not just the API: a subpacket whose
        // length field is 1 carries only its type octet (an empty body), which the parser now
        // rejects with a MalformedPacketException wrapping the constructor's exception.
        isWireDecodeRejected(SignatureSubpacketTags.FEATURES, 1);
        isWireDecodeRejected(SignatureSubpacketTags.TRUST_SIG, 2);
        isWireDecodeRejected(SignatureSubpacketTags.NOTATION_DATA, notationBody(2, 2, 0));
    }

    /**
     * The Signature Creation Time, Signature Expiration Time, Key Expiration Time, Issuer Key ID,
     * Exportable Certification, Revocable and Primary User ID subpackets all have a body of a fixed
     * length that their accessor requires: a 4-octet time field (RFC 9580 sec. 5.2.3.11, 5.2.3.18
     * and 5.2.3.13), an 8-octet key ID (sec. 5.2.3.12) or a 1-octet flag "zero or one"
     * (sec. 5.2.3.19, 5.2.3.20 and 5.2.3.27). A body of any other length has to be rejected when
     * the subpacket is parsed rather than at the accessor, which reports it as an unchecked
     * {@link IllegalStateException} from {@code Utils.timeFromBytes} /
     * {@code Utils.booleanFromByteArray} - a certificate carrying such a body in a self-signature
     * is signed content, so it passes signature verification and only fails later when an ordinary
     * reader asks for the key expiry or the export policy (github #2426).
     */
    private void testFixedLengthSubpacketsRejected()
            throws IOException
    {
        // getTime() reads a 4-octet time field
        String[] timeSubpackets = new String[]{"SignatureCreationTime", "SignatureExpirationTime", "KeyExpirationTime"};
        for (int i = 0; i != timeSubpackets.length; i++)
        {
            isConstructionRejected(timeSubpackets[i], new byte[0]);
            isConstructionRejected(timeSubpackets[i], new byte[]{1});
            isConstructionRejected(timeSubpackets[i], new byte[]{0, 0, 0});
            isConstructionRejected(timeSubpackets[i], new byte[]{0, 0, 0, 0, 1});
        }

        // getKeyID() reads an 8-octet key ID
        isConstructionRejected("IssuerKeyID", new byte[0]);
        isConstructionRejected("IssuerKeyID", new byte[7]);

        // the flag subpackets carry a single octet, and it is a 0 or a 1
        String[] flagSubpackets = new String[]{"Exportable", "Revocable", "PrimaryUserID"};
        for (int i = 0; i != flagSubpackets.length; i++)
        {
            isConstructionRejected(flagSubpackets[i], new byte[0]);
            isConstructionRejected(flagSubpackets[i], new byte[]{1, 0});
            isConstructionRejected(flagSubpackets[i], new byte[]{2});
            isConstructionRejected(flagSubpackets[i], new byte[]{(byte)0xff});
        }

        testFixedLengthBodiesAccepted();

        // the wrong-length body is reachable from the wire: a subpacket whose declared length
        // matches the octets it carries passes the parser's range and truncation checks, so the
        // constructor is the only place the fixed length can be enforced.
        isWireDecodeRejected(SignatureSubpacketTags.CREATION_TIME, new byte[]{1});
        isWireDecodeRejected(SignatureSubpacketTags.EXPIRE_TIME, new byte[]{0, 0, 0, 0, 1});
        isWireDecodeRejected(SignatureSubpacketTags.KEY_EXPIRE_TIME, new byte[]{1});
        isWireDecodeRejected(SignatureSubpacketTags.ISSUER_KEY_ID, new byte[]{1});
        isWireDecodeRejected(SignatureSubpacketTags.EXPORTABLE, new byte[]{1, 0});
        isWireDecodeRejected(SignatureSubpacketTags.REVOCABLE, new byte[]{2});
        isWireDecodeRejected(SignatureSubpacketTags.PRIMARY_USER_ID, new byte[]{1, 0});
    }

    private void testFixedLengthBodiesAccepted()
            throws IOException
    {
        SignatureCreationTime creationTime = new SignatureCreationTime(false, false, new byte[]{0, 0, 0, 1});
        isTrue("SignatureCreationTime mismatch", creationTime.getTime().getTime() == 1000L);

        SignatureExpirationTime expirationTime = new SignatureExpirationTime(false, false, new byte[]{0, 0, 1, 0});
        isTrue("SignatureExpirationTime mismatch", expirationTime.getTime() == 256L);

        KeyExpirationTime keyExpirationTime = new KeyExpirationTime(false, false, new byte[]{(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff});
        isTrue("KeyExpirationTime mismatch", keyExpirationTime.getTime() == 0xFFFFFFFFL);

        IssuerKeyID issuerKeyID = new IssuerKeyID(false, false, new byte[]{0, 0, 0, 0, 0, 0, 0, 1});
        isTrue("IssuerKeyID mismatch", issuerKeyID.getKeyID() == 1L);

        isTrue("Exportable(0) mismatch", !new Exportable(false, false, new byte[]{0}).isExportable());
        isTrue("Exportable(1) mismatch", new Exportable(false, false, new byte[]{1}).isExportable());
        isTrue("Revocable(0) mismatch", !new Revocable(false, false, new byte[]{0}).isRevocable());
        isTrue("Revocable(1) mismatch", new Revocable(false, false, new byte[]{1}).isRevocable());
        isTrue("PrimaryUserID(0) mismatch", !new PrimaryUserID(false, false, new byte[]{0}).isPrimaryUserID());
        isTrue("PrimaryUserID(1) mismatch", new PrimaryUserID(false, false, new byte[]{1}).isPrimaryUserID());

        // the parser's tolerance of a fixed-length field whose declared length overruns the end of
        // the subpacket area (the body is truncated to the fixed length) has to survive the check:
        // here a Key Expiration Time declares a 9-octet body and carries the 4 octets it should.
        byte[] encoded = new byte[]{10, SignatureSubpacketTags.KEY_EXPIRE_TIME, 0, 0, 0, 1};
        SignatureSubpacket parsed = new SignatureSubpacketInputStream(
                new ByteArrayInputStream(encoded)).readPacket();
        isTrue("Miscoded Key Expiration Time length not tolerated",
                ((KeyExpirationTime)parsed).getTime() == 1L);
    }

    private void isConstructionRejected(String name, byte[] body)
    {
        try
        {
            construct(name, body);
            fail(name + " accepted a malformed " + body.length + "-octet body");
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
        if (name.equals("SignatureCreationTime"))
        {
            return new SignatureCreationTime(false, false, body);
        }
        if (name.equals("SignatureExpirationTime"))
        {
            return new SignatureExpirationTime(false, false, body);
        }
        if (name.equals("KeyExpirationTime"))
        {
            return new KeyExpirationTime(false, false, body);
        }
        if (name.equals("IssuerKeyID"))
        {
            return new IssuerKeyID(false, false, body);
        }
        if (name.equals("Exportable"))
        {
            return new Exportable(false, false, body);
        }
        if (name.equals("Revocable"))
        {
            return new Revocable(false, false, body);
        }
        if (name.equals("PrimaryUserID"))
        {
            return new PrimaryUserID(false, false, body);
        }
        throw new IllegalStateException("unknown subpacket: " + name);
    }

    /**
     * Build a raw NotationData body: the 8-octet header (4 flag octets, a 2-octet name length
     * and a 2-octet value length) followed by {@code payloadLength} body octets. Passing a
     * payloadLength smaller than {@code nameLength + valueLength} yields a truncated packet.
     */
    private byte[] notationBody(int nameLength, int valueLength, int payloadLength)
    {
        byte[] body = new byte[8 + payloadLength];
        body[4] = (byte)(nameLength >>> 8);
        body[5] = (byte)nameLength;
        body[6] = (byte)(valueLength >>> 8);
        body[7] = (byte)valueLength;
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

        // a NotationData body exactly 8 + nameLength + valueLength long is accepted and its
        // name/value accessors read back correctly. Here name = "x" (1 octet), value empty.
        byte[] notation = notationBody(1, 0, 1);
        notation[8] = (byte)'x';
        NotationData notationData = new NotationData(false, false, notation);
        isTrue("NotationData name mismatch", notationData.getNotationName().equals("x"));
        isTrue("NotationData value should be empty", notationData.getNotationValueBytes().length == 0);
    }

    private void isWireDecodeRejected(int type, int subpacketLength)
            throws IOException
    {
        // OpenPGP signature subpacket framing: a one-octet length field (< 192) covering the
        // type octet plus body, the type octet, then (subpacketLength - 1) body octets (left
        // zero here so the body is too short for the subpacket's accessors).
        byte[] encoded = new byte[1 + subpacketLength];
        encoded[0] = (byte)subpacketLength;
        encoded[1] = (byte)type;

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

    private void isWireDecodeRejected(int type, byte[] body)
            throws IOException
    {
        // as above, but with a caller-supplied body (for subpackets like NotationData whose
        // truncation depends on internal length fields rather than a fixed minimum length).
        byte[] encoded = new byte[1 + 1 + body.length];
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
