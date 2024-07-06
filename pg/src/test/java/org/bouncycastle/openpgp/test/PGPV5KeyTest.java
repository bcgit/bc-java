package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class PGPV5KeyTest
        extends AbstractPgpKeyPairTest
{

    @Override
    public String getName()
    {
        return "PGPV5KeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        parseAndEncodeKey();
        parseCertificateAndVerifyKeySigs();
    }

    private void parseAndEncodeKey()
            throws IOException
    {
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "lGEFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd\n" +
                "fj75iux+my8QAAAAAAAiAQCHZ1SnSUmWqxEsoI6facIVZQu6mph3cBFzzTvcm5lA\n" +
                "Ng5ctBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0e8mHJGQC\n" +
                "X5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyICAQYVCgkI\n" +
                "CwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3wwJAXRJy9\n" +
                "M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2BZxmBVyR9OQSAAAA\n" +
                "MgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0YvYWWAoD\n" +
                "AQgHAAAAAAAiAP9OdAPppjU1WwpqjIItkxr+VPQRT8Zm/Riw7U3F6v3OiBFHiHoF\n" +
                "GBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACRWVabVAUCXJH05AIb\n" +
                "DAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijhob2U5AQC+RtOHCHx7\n" +
                "TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==\n" +
                "=IiS2\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        ByteArrayInputStream bIn = new ByteArrayInputStream(KEY.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(aIn, bOut);
        byte[] hex = bOut.toByteArray();

        bIn = new ByteArrayInputStream(hex);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);

        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        Iterator<PGPPublicKey> it = secretKeys.getPublicKeys();
        isEncodingEqual("Fingerprint mismatch for the primary key.",
                Hex.decode("19347BC9872464025F99DF3EC2E0000ED9884892E1F7B3EA4C94009159569B54"), it.next().getFingerprint());
        isEncodingEqual("Fingerprint mismatch for the subkey.",
                Hex.decode("E4557C2B02FFBF4B04F87401EC336AF7133D0F85BE7FD09BAEFD9CAEB8C93965"), it.next().getFingerprint());

        bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.LEGACY);
        secretKeys.encode(pOut);
        pOut.close();
        isEncodingEqual("Encoded representation MUST match", hex, bOut.toByteArray());
    }

    private void parseCertificateAndVerifyKeySigs()
            throws IOException, PGPException {
        String CERT = "\n" +
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "mDcFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd\n" +
                "fj75iux+my8QtBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0\n" +
                "e8mHJGQCX5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyIC\n" +
                "AQYVCgkICwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3w\n" +
                "wJAXRJy9M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2Bbg8BVyR\n" +
                "9OQSAAAAMgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0\n" +
                "YvYWWAoDAQgHiHoFGBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACR\n" +
                "WVabVAUCXJH05AIbDAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijho\n" +
                "b2U5AQC+RtOHCHx7TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==\n" +
                "=WYfO\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        ByteArrayInputStream bIn = new ByteArrayInputStream(CERT.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(aIn, bOut);
        byte[] hex = bOut.toByteArray();

        bIn = new ByteArrayInputStream(hex);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPPublicKeyRing cert = (PGPPublicKeyRing) objFac.nextObject();

        Iterator<PGPPublicKey> it = cert.getPublicKeys();
        isEncodingEqual("Fingerprint mismatch for the primary key.",
                Hex.decode("19347BC9872464025F99DF3EC2E0000ED9884892E1F7B3EA4C94009159569B54"), it.next().getFingerprint());
        isEncodingEqual("Fingerprint mismatch for the subkey.",
                Hex.decode("E4557C2B02FFBF4B04F87401EC336AF7133D0F85BE7FD09BAEFD9CAEB8C93965"), it.next().getFingerprint());

        bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.LEGACY);
        cert.encode(pOut);
        pOut.close();

        isEncodingEqual("Cert encoding MUST match",
                hex, bOut.toByteArray());

        it = cert.getPublicKeys();
        PGPPublicKey primaryKey = it.next();
        PGPPublicKey subKey = it.next();

        String uid = primaryKey.getUserIDs().next();
        isEquals("UserID mismatch", "emma.goldman@example.net", uid);

        PGPSignature uidBinding = primaryKey.getSignaturesForID(uid).next();
        uidBinding.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("User-ID binding signature MUST verify",
                uidBinding.verifyCertification(uid, primaryKey));

        PGPSignature subkeyBinding = subKey.getSignatures().next();
        subkeyBinding.init(new BcPGPContentVerifierBuilderProvider(), primaryKey);
        isTrue("Subkey binding signature MUST verify",
                subkeyBinding.verifyCertification(primaryKey, subKey));
    }

    public static void main(String[] args)
    {
        runTest(new PGPV5KeyTest());
    }
}
