package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class OpenPgpMessageTest
        extends AbstractPacketTest
{

    /*
    Inline-signed message using a version 6 signature
    see https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-inline-signed-messag
    */
    public static final String INLINE_SIGNED = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "xEYGAQobIHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usyxhsTwYJppfk\n" +
            "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkBy0p1AAAAAABXaGF0IHdlIG5lZWQgZnJv\n" +
            "bSB0aGUgZ3JvY2VyeSBzdG9yZToKCi0gdG9mdQotIHZlZ2V0YWJsZXMKLSBub29k\n" +
            "bGVzCsKYBgEbCgAAACkFgmOYo2MiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l\n" +
            "JewnutmsyQAAAABpNiB2SV9QIYiQ9/Xi7jwYIlFPcFAPVR2G5ckh5ATjSlP7rCfQ\n" +
            "b7gKqPxbyxbhljGygHQPnqau1eBzrQD5QVplPEDnemrnfmkrpx0GmhCfokxYz9jj\n" +
            "FtCgazStmsuOXF9SFQE=\n" +
            "-----END PGP MESSAGE-----";

    /*
    Cleartext-signed message using a version 6 signature
    see https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-cleartext-signed-mes
     */
    public static final String CLEARTEXT_SIGNED = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "\n" +
            "What we need from the grocery store:\n" +
            "\n" +
            "- - tofu\n" +
            "- - vegetables\n" +
            "- - noodles\n" +
            "\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo\n" +
            "/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr\n" +
            "NK2ay45cX1IVAQ==\n" +
            "-----END PGP SIGNATURE-----";

    // Content of the message's LiteralData packet
    public static final String CONTENT = "What we need from the grocery store:\n" +
            "\n" +
            "- tofu\n" +
            "- vegetables\n" +
            "- noodles\n";
    // Issuer of the message
    public static byte[] ISSUER = Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
    // Salt used to generate the signature
    public static byte[] SALT = Hex.decode("76495F50218890F7F5E2EE3C1822514F70500F551D86E5C921E404E34A53FBAC");


    private void testParseV6CleartextSignedMessage()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(CLEARTEXT_SIGNED.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);

        isNull("The ASCII armored input stream MUST NOT hallucinate headers where there are non",
                aIn.getArmorHeaders()); // We do not have any header lines after the armor header

        // Parse and compare literal data
        ByteArrayOutputStream litOut = new ByteArrayOutputStream();
        while (aIn.isClearText())
        {
            litOut.write(aIn.read());
        }
        String c = litOut.toString();
        isEquals("Mismatching content of the cleartext-signed test message",
                CONTENT, c.substring(0, c.length() - 2)); // compare ignoring last '\n'

        BCPGInputStream pIn = new BCPGInputStream(aIn);
        // parse and compare signature
        SignaturePacket sig = (SignaturePacket) pIn.readPacket();
        compareSignature(sig);
    }

    private void testParseV6InlineSignedMessage()
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(INLINE_SIGNED.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        // Parse and compare the OnePassSignature packet
        OnePassSignaturePacket ops = (OnePassSignaturePacket) pIn.readPacket();
        isEquals("OPS packet MUST be of version 6",
                OnePassSignaturePacket.VERSION_6, ops.getVersion());
        isEncodingEqual("OPS packet issuer fingerprint mismatch",
                ISSUER, ops.getFingerprint());
        isEncodingEqual("OPS packet salt mismatch",
                SALT, ops.getSalt());
        isTrue("OPS packet isContaining mismatch",
                ops.isContaining());

        // Parse and compare the LiteralData packet
        LiteralDataPacket lit = (LiteralDataPacket) pIn.readPacket();
        compareLiteralData(lit);

        // Parse and compare the Signature packet
        SignaturePacket sig = (SignaturePacket) pIn.readPacket();
        compareSignature(sig);
    }


    private void compareLiteralData(LiteralDataPacket lit)
            throws IOException
    {
        isEquals("LiteralDataPacket format mismatch",
                PGPLiteralData.UTF8, lit.getFormat());
        isEquals("LiteralDataPacket mod data mismatch",
                0, lit.getModificationTime());
        byte[] content = lit.getInputStream().readAll();
        String contentString = new String(content, StandardCharsets.UTF_8);
        isEquals("LiteralDataPacket content mismatch",
                CONTENT, contentString);
    }

    private void compareSignature(SignaturePacket sig)
    {
        isEquals("SignaturePacket version mismatch",
                SignaturePacket.VERSION_6, sig.getVersion());
        isEquals("SignaturePacket signature type mismatch",
                PGPSignature.CANONICAL_TEXT_DOCUMENT, sig.getSignatureType());
        isEquals("SignaturePacket key algorithm mismatch",
                PublicKeyAlgorithmTags.Ed25519, sig.getKeyAlgorithm());
        isEquals("SignaturePacket hash algorithm mismatch",
                HashAlgorithmTags.SHA512, sig.getHashAlgorithm());
        isTrue("SignaturePacket salt mismatch",
                Arrays.areEqual(SALT, sig.getSalt()));
        // hashed subpackets
        isEquals("SignaturePacket number of hashed packets mismatch",
                2, sig.getHashedSubPackets().length);
        SignatureCreationTime creationTimeSubpacket = (SignatureCreationTime) sig.getHashedSubPackets()[0];
        isEquals("SignaturePacket signature creation time mismatch",
                1670947683000L, creationTimeSubpacket.getTime().getTime());
        IssuerFingerprint issuerSubpacket = (IssuerFingerprint) sig.getHashedSubPackets()[1];
        isEncodingEqual("SignaturePacket issuer fingerprint mismatch",
                ISSUER, issuerSubpacket.getFingerprint());
        // unhashed subpackets
        isEquals("SignaturePacket number of unhashed packets mismatch",
                0, sig.getUnhashedSubPackets().length);
    }

    @Override
    public String getName()
    {
        return "OpenPgpMessageTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testParseV6CleartextSignedMessage();
        testParseV6InlineSignedMessage();
    }

    public static void main(String[] args)
    {
        runTest(new OpenPgpMessageTest());
    }
}
