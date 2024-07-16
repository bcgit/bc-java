package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class OnePassSignaturePacketTest
        extends AbstractPacketTest
{

    // Parse v6 OPS packet and compare its values to a known-good test vector
    private void testParseV6OnePassSignaturePacket()
            throws IOException
    {
        // Version 6 OnePassSignature packet
        // extracted from https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-inline-signed-messag
        byte[] encOPS = Hex.decode("c44606010a1b2076495f50218890f7f5e2ee3c1822514f70500f551d86e5c921e404e34a53fbaccb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc901");
        // Issuer of the message
        byte[] issuerFp = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
        // Salt used to generate the signature
        byte[] salt = Hex.decode("76495F50218890F7F5E2EE3C1822514F70500F551D86E5C921E404E34A53FBAC");

        ByteArrayInputStream bIn = new ByteArrayInputStream(encOPS);
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        // Parse and compare the OnePassSignature packet
        OnePassSignaturePacket ops = (OnePassSignaturePacket) pIn.readPacket();
        isEquals("OPS packet MUST be of version 6",
                OnePassSignaturePacket.VERSION_6, ops.getVersion());
        isEncodingEqual("OPS packet issuer fingerprint mismatch",
                issuerFp, ops.getFingerprint());
        isTrue("OPS packet key-ID mismatch",
                // key-ID are the first 8 octets of the fingerprint
                Hex.toHexString(issuerFp).startsWith(Long.toHexString(ops.getKeyID())));
        isEncodingEqual("OPS packet salt mismatch",
                salt, ops.getSalt());
        isTrue("OPS packet isContaining mismatch",
                ops.isContaining());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, true);
        ops.encode(pOut);
        pOut.close();

        isEncodingEqual("OPS Packet encoding mismatch", encOPS, bOut.toByteArray());
    }

    private void roundtripV3Packet()
            throws IOException
    {
        OnePassSignaturePacket before = new OnePassSignaturePacket(
                PGPSignature.BINARY_DOCUMENT,
                HashAlgorithmTags.SHA256,
                PublicKeyAlgorithmTags.RSA_GENERAL,
                123L,
                true);

        isEquals("Expected OPS version 3",
                OnePassSignaturePacket.VERSION_3, before.getVersion());
        isEquals("Signature type mismatch",
                PGPSignature.BINARY_DOCUMENT, before.getSignatureType());
        isEquals("Hash Algorithm mismatch",
                HashAlgorithmTags.SHA256, before.getHashAlgorithm());
        isEquals("Pulic Key Algorithm mismatch",
                PublicKeyAlgorithmTags.RSA_GENERAL, before.getKeyAlgorithm());
        isEquals("Key-ID mismatch",
                123L, before.getKeyID());
        isFalse("OPS is expected to be non-containing",
                before.isContaining());
        isNull("OPS v3 MUST NOT have a fingerprint",
                before.getFingerprint());
        isNull("OPS v3 MUST NOT have salt",
                before.getSalt());

        for (boolean newTypeIdFormat : new boolean[] {true, false})
        {
            // round-trip the packet by encoding and decoding it
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            BCPGOutputStream pOut = new BCPGOutputStream(bOut, newTypeIdFormat);
            before.encode(pOut);
            pOut.close();
            ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
            BCPGInputStream pIn = new BCPGInputStream(bIn);
            OnePassSignaturePacket after = (OnePassSignaturePacket) pIn.readPacket();

            isEquals("round-tripped OPS version mismatch",
                    before.getVersion(), after.getVersion());
            isEquals("round-tripped OPS signature type mismatch",
                    before.getSignatureType(), after.getSignatureType());
            isEquals("round-tripped OPS hash algorithm mismatch",
                    before.getHashAlgorithm(), after.getHashAlgorithm());
            isEquals("round-tripped OPS public key algorithm mismatch",
                    before.getKeyAlgorithm(), after.getKeyAlgorithm());
            isEquals("round-tripped OPS key-id mismatch",
                    before.getKeyID(), after.getKeyID());
            isEquals("round-tripped OPS nested flag mismatch",
                    before.isContaining(), after.isContaining());
            isNull("round-tripped OPS v3 MUST NOT have fingerprint",
                    after.getFingerprint());
            isNull("round-tripped OPS v3 MUST NOT have salt",
                    after.getSalt());

            if (before.hasNewPacketFormat() && newTypeIdFormat)
            {
                isEncodingEqual(before, after);
            }
        }
    }

    private void roundtripV6Packet()
            throws IOException
    {
        byte[] salt = new byte[32];
        byte[] fingerprint = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
        long keyID = FingerprintUtil.keyIdFromV6Fingerprint(fingerprint);

        new SecureRandom().nextBytes(salt);
        OnePassSignaturePacket before = new OnePassSignaturePacket(
                PGPSignature.CANONICAL_TEXT_DOCUMENT,
                HashAlgorithmTags.SHA512,
                PublicKeyAlgorithmTags.EDDSA_LEGACY,
                salt,
                fingerprint,
                false);

        isEquals("Expected OPS version 6",
                OnePassSignaturePacket.VERSION_6, before.getVersion());
        isEquals("Signature type mismatch",
                PGPSignature.CANONICAL_TEXT_DOCUMENT, before.getSignatureType());
        isEquals("Hash algorithm mismatch",
                HashAlgorithmTags.SHA512, before.getHashAlgorithm());
        isEquals("Public key algorithm mismatch",
                PublicKeyAlgorithmTags.EDDSA_LEGACY, before.getKeyAlgorithm());
        isEncodingEqual("Salt mismatch",
                salt, before.getSalt());
        isEncodingEqual("Fingerprint mismatch",
                fingerprint, before.getFingerprint());
        isEquals("Derived key-ID mismatch",
                keyID, before.getKeyID());
        isTrue("non-nested OPS is expected to be containing",
                before.isContaining());

        for (boolean newTypeIdFormat : new boolean[] {true, false})
        {
            // round-trip the packet by encoding and decoding it
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            BCPGOutputStream pOut = new BCPGOutputStream(bOut, newTypeIdFormat);
            before.encode(pOut);
            pOut.close();
            ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
            BCPGInputStream pIn = new BCPGInputStream(bIn);
            OnePassSignaturePacket after = (OnePassSignaturePacket) pIn.readPacket();

            isEquals("round-tripped OPS version mismatch",
                    before.getVersion(), after.getVersion());
            isEquals("round-tripped OPS signature type mismatch",
                    before.getSignatureType(), after.getSignatureType());
            isEquals("round-tripped OPS hash algorithm mismatch",
                    before.getHashAlgorithm(), after.getHashAlgorithm());
            isEquals("round-tripped OPS public key algorithm mismatch",
                    before.getKeyAlgorithm(), after.getKeyAlgorithm());
            isEquals("round-tripped OPS key-id mismatch",
                    before.getKeyID(), after.getKeyID());
            isEquals("round-tripped OPS nested flag mismatch",
                    before.isContaining(), after.isContaining());
            isEncodingEqual("round-tripped OPS fingerprint mismatch",
                    before.getFingerprint(), after.getFingerprint());
            isEncodingEqual("round-tripped OPS salt mismatch",
                    before.getSalt(), after.getSalt());

            if (before.hasNewPacketFormat() && newTypeIdFormat)
            {
                isEncodingEqual(before, after);
            }
        }
    }

    private void roundtripV6PacketWithZeroLengthSalt()
            throws IOException
    {
        byte[] salt = new byte[0];
        byte[] fingerprint = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");

        OnePassSignaturePacket before = new OnePassSignaturePacket(
                PGPSignature.CANONICAL_TEXT_DOCUMENT,
                HashAlgorithmTags.SHA512,
                PublicKeyAlgorithmTags.EDDSA_LEGACY,
                salt,
                fingerprint,
                false);

        isEncodingEqual("Salt mismatch",
                salt, before.getSalt());

        for (boolean newTypeIdFormat : new boolean[] {true, false})
        {
            // round-trip the packet by encoding and decoding it
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            BCPGOutputStream pOut = new BCPGOutputStream(bOut, newTypeIdFormat);
            before.encode(pOut);
            pOut.close();
            ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
            BCPGInputStream pIn = new BCPGInputStream(bIn);
            OnePassSignaturePacket after = (OnePassSignaturePacket) pIn.readPacket();

            isEquals("round-tripped OPS version mismatch",
                    before.getVersion(), after.getVersion());
            isEquals("round-tripped OPS signature type mismatch",
                    before.getSignatureType(), after.getSignatureType());
            isEquals("round-tripped OPS hash algorithm mismatch",
                    before.getHashAlgorithm(), after.getHashAlgorithm());
            isEquals("round-tripped OPS public key algorithm mismatch",
                    before.getKeyAlgorithm(), after.getKeyAlgorithm());
            isEquals("round-tripped OPS key-id mismatch",
                    before.getKeyID(), after.getKeyID());
            isEquals("round-tripped OPS nested flag mismatch",
                    before.isContaining(), after.isContaining());
            isEncodingEqual("round-tripped OPS fingerprint mismatch",
                    before.getFingerprint(), after.getFingerprint());
            isEncodingEqual("round-tripped OPS salt mismatch",
                    before.getSalt(), after.getSalt());
        }
    }

    private void parsingOfPacketWithUnknownVersionFails()
    {
        // Version 0x99 OnePassSignature packet
        byte[] encOPS = Hex.decode("c44699010a1b2076495f50218890f7f5e2ee3c1822514f70500f551d86e5c921e404e34a53fbaccb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc901");

        ByteArrayInputStream bIn = new ByteArrayInputStream(encOPS);
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        try
        {
            pIn.readPacket();
            fail("Expected UnsupportedPacketVersionException");
        }
        catch (IOException e)
        {
            fail("Expected UnsupportedPacketVersionException", e);
        }
        catch (UnsupportedPacketVersionException e)
        {
            // expected
        }
    }

    private void parsingOfPacketWithTruncatedFingerprintFails()
    {
        // Version 6 OnePassSignature packet with truncated fingerprint field (20 bytes instead of 32)
        // This error would happen, if a v6 OPS packet was generated with a v4 fingerprint.
        // extracted from https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-inline-signed-messag
        byte[] encOPS = Hex.decode("c44606010a1b2076495f50218890f7f5e2ee3c1822514f70500f551d86e5c921e404e34a53fbaccb186c4f0609a697e4d52dfa6c722b0c1f1e27c101");

        ByteArrayInputStream bIn = new ByteArrayInputStream(encOPS);
        BCPGInputStream pIn = new BCPGInputStream(bIn);

        try
        {
            pIn.readPacket();
            fail("Expected IOException");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    @Override
    public String getName()
    {
        return "OnePassSignaturePacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testParseV6OnePassSignaturePacket();
        roundtripV3Packet();
        roundtripV6Packet();
        parsingOfPacketWithUnknownVersionFails();
        parsingOfPacketWithTruncatedFingerprintFails();
        roundtripV6PacketWithZeroLengthSalt();
    }

    public static void main(String[] args)
    {
        runTest(new OnePassSignaturePacketTest());
    }
}
