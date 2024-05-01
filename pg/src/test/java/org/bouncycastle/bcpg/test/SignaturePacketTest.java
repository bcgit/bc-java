package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SignaturePacketTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "SignaturePacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testParseV6Signature();
        testParseV4Ed25519LegacySignature();
        testParseUnknownVersionSignaturePacket();
    }

    private void testParseV6Signature()
            throws IOException
    {
        // Hex-encoded OpenPGP v6 signature packet
        // Extracted from https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-inline-signed-messag
        byte[] encSigPacket = Hex.decode("c29806011b0a0000002905826398a363222106cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc90000000069362076495f50218890f7f5e2ee3c1822514f70500f551d86e5c921e404e34a53fbac27d06fb80aa8fc5bcb16e19631b280740f9ea6aed5e073ad00f9415a653c40e77a6ae77e692ba71d069a109fa24c58cfd8e316d0a06b34ad9acb8e5c5f521501");
        // Issuer of the message
        byte[] issuerFP = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
        // Salt used to generate the signature
        byte[] salt = Hex.decode("76495F50218890F7F5E2EE3C1822514F70500F551D86E5C921E404E34A53FBAC");

        ByteArrayInputStream bIn = new ByteArrayInputStream(encSigPacket);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        SignaturePacket sig = (SignaturePacket) pIn.readPacket();

        isEquals("SignaturePacket version mismatch",
                SignaturePacket.VERSION_6, sig.getVersion());
        isEquals("SignaturePacket signature type mismatch",
                PGPSignature.CANONICAL_TEXT_DOCUMENT, sig.getSignatureType());
        isEquals("SignaturePacket key algorithm mismatch",
                PublicKeyAlgorithmTags.Ed25519, sig.getKeyAlgorithm());
        isEquals("SignaturePacket hash algorithm mismatch",
                HashAlgorithmTags.SHA512, sig.getHashAlgorithm());
        isEncodingEqual("SignaturePacket salt mismatch",
                salt, sig.getSalt());
        // hashed subpackets
        isEquals("SignaturePacket number of hashed packets mismatch",
                2, sig.getHashedSubPackets().length);
        SignatureCreationTime creationTimeSubpacket = (SignatureCreationTime) sig.getHashedSubPackets()[0];
        isEquals("SignaturePacket signature creation time mismatch",
                1670947683000L, creationTimeSubpacket.getTime().getTime());
        IssuerFingerprint issuerSubpacket = (IssuerFingerprint) sig.getHashedSubPackets()[1];
        isEncodingEqual("SignaturePacket issuer fingerprint mismatch",
                issuerFP, issuerSubpacket.getFingerprint());
        // unhashed subpackets
        isEquals("SignaturePacket number of unhashed packets mismatch",
                0, sig.getUnhashedSubPackets().length);

        // v6 Ed25519 signatures (not LEGACY) do not use MPI encoding for the raw signature
        //  but rather encode into octet strings
        isNull("Signature MPI encoding MUST be null",
                sig.getSignature());
        isEncodingEqual("Signature octet string encoding mismatch",
                Hex.decode("27d06fb80aa8fc5bcb16e19631b280740f9ea6aed5e073ad00f9415a653c40e77a6ae77e692ba71d069a109fa24c58cfd8e316d0a06b34ad9acb8e5c5f521501"),
                sig.getSignatureBytes());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, true);
        sig.encode(pOut);
        pOut.close();

        isEncodingEqual("SignaturePacket encoding mismatch", encSigPacket, bOut.toByteArray());
    }

    private void testParseV4Ed25519LegacySignature()
            throws IOException
    {
        // Hex-encoded v4 test signature
        //  see https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v4-ed25519legacy-sig
        byte[] encSigPacket = Hex.decode("885e040016080006050255f95f95000a09108cfde12197965a9af62200ff56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed33660100d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404");
        ByteArrayInputStream bIn = new ByteArrayInputStream(encSigPacket);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        SignaturePacket sig = (SignaturePacket) pIn.readPacket();

        isEquals("SignaturePacket version mismatch",
                SignaturePacket.VERSION_4, sig.getVersion());
        isEquals("SignaturePacket signature type mismatch",
                PGPSignature.BINARY_DOCUMENT, sig.getSignatureType());
        isEquals("SignaturePacket public key algorithm mismatch",
                PublicKeyAlgorithmTags.EDDSA_LEGACY, sig.getKeyAlgorithm());
        isEquals("SignaturePacket hash algorithm mismatch",
                HashAlgorithmTags.SHA256, sig.getHashAlgorithm());
        isEquals("SignaturePacket number of hashed subpackets mismatch",
                1, sig.getHashedSubPackets().length);
        SignatureCreationTime creationTimeSubpacket = (SignatureCreationTime) sig.getHashedSubPackets()[0];
        isEquals("SignaturePacket creationTime mismatch",
                1442406293000L, creationTimeSubpacket.getTime().getTime());
        isEquals("SignaturePacket number of unhashed subpackets mismatch",
                1, sig.getUnhashedSubPackets().length);
        IssuerKeyID issuerKeyID = (IssuerKeyID) sig.getUnhashedSubPackets()[0];
        isEquals("SignaturePacket issuer key-id mismatch",
                -8287220204898461030L, issuerKeyID.getKeyID());

        // EDDSA_LEGACY uses MPI encoding for the raw signature value
        MPInteger[] mpInts = sig.getSignature();
        isEquals("Signature MPI encoding mismatch",
                2, mpInts.length);
        isEncodingEqual("Signature MPI encoding in signatureBytes field mismatch",
                Hex.decode("00ff56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed33660100d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404"),
                sig.getSignatureBytes());

        // v4 signatures do not have salt
        isNull("Salt MUST be null", sig.getSalt());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, false);
        sig.encode(pOut);
        pOut.close();

        isEncodingEqual("SignaturePacket encoding mismatch",
                encSigPacket, bOut.toByteArray());
    }

    private void testParseUnknownVersionSignaturePacket()
    {
        // Hex-encoded signature with version 0x99
        byte[] encSigPacket = Hex.decode("885e990016080006050255f95f95000a09108cfde12197965a9af62200ff56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed33660100d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404");
        ByteArrayInputStream bIn = new ByteArrayInputStream(encSigPacket);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        Exception ex = testException("unsupported version: 153",
                "UnsupportedPacketVersionException",
                new TestExceptionOperation()
                {
                    @Override
                    public void operation()
                            throws Exception
                    {
                        SignaturePacket sig = (SignaturePacket) pIn.readPacket();
                    }
                });
        isNotNull("Parsing SignaturePacket of version 0x99 MUST throw UnsupportedPacketVersionException.", ex);
    }

    public static void main(String[] args)
    {
        runTest(new SignaturePacketTest());
    }
}
