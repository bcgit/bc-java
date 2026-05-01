package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class PGPv6MessageDecryptionTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "PGPv6MessageDecryptionTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        decryptMessageEncryptedUsingPKESKv6();
        decryptMessageUsingV6GopenpgpTestKey();
        decryptMessageUsingSessionKey();
    }

    private void decryptMessageEncryptedUsingPKESKv6()
            throws IOException, PGPException
    {
        // X25519 test key from rfc9580
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
                "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
                "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
                "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
                "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
                "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
                "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
                "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
                "k0mXubZvyl4GBg==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(key));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        pIn.close();
        aIn.close();
        bIn.close();

        // created using rpgpie 0.1.1 (rpgp 0.14.0-alpha.0)
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRk5Bu/DU62hzgRm\n" +
                "JYvBYeLA2Nrmz15g69ZN0xAB7SLDRCjjhnK6V7fGns6P1EiSCYbl1uNVBhK0MPGe\n" +
                "rU9FY4yUXTnbB6eIXdCw0loCCQIOu95D17wvJJC2a96ou9SGPIoA4Q2dMH5BMS9Z\n" +
                "veq3AGgIBdJMF8Ft8PBE30R0cba1O5oQC0Eiscw7fkNnYGuSXagqNXdOBkHDN0fk\n" +
                "VWFrxQRbxEVYUWc=\n" +
                "=u2kL\n" +
                "-----END PGP MESSAGE-----\n";
        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(MSG));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);

        isEquals("PKESK version mismatch",
                PublicKeyEncSessionPacket.VERSION_6, encData.getVersion());
        isEquals("Public key algorithm mismatch",
                PublicKeyAlgorithmTags.X25519, encData.getAlgorithm());
        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyID()); // TODO: getKeyIdentifier()
        isNotNull("Decryption key MUST be identifiable", decryptionKey);
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decryptor = new BcPublicKeyDataDecryptorFactory(privateKey);
        InputStream decrypted = encData.getDataStream(decryptor);
        PGPObjectFactory decFac = new BcPGPObjectFactory(decrypted);
        PGPLiteralData lit = (PGPLiteralData) decFac.nextObject();
        isEncodingEqual("Message plaintext mismatch",
                Strings.toUTF8ByteArray("Hello World :)"),
                Streams.readAll(lit.getDataStream()));
    }

    private void decryptMessageUsingV6GopenpgpTestKey()
            throws IOException, PGPException
    {
        // Ed448/X448 test key
        // Courtesy of @twiss from Proton
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xX0GZrnFtRwAAAA5wl2q+bhfNkzHsxlLowaUy0sTOeAsmhseHBvPKKc7yehR\n" +
                "8Qs93LbjQHjw3IaqduMRDRs4pZJyV/+AACKFtkkC3ebcyaOvHGaJpc9rx0Z1\n" +
                "4YHdd4BG1AJvZuhk8pJ6dQuuQeFtBsQctoktFwlDh0XjnjUrkMLALQYfHAoA\n" +
                "AABMBYJmucW1AwsJBwUVCAoMDgQWAAIBApsDAh4JIqEGEvURGalOLHznAmcI\n" +
                "MRsEHorGZ2ikxHawiPyOMw+CAOANJwkDBwMJAQcBCQIHAgAAAACbfCBvUoq6\n" +
                "bon1bSsp9HLc829xjDINBOvegmk4tMKv392c1LNPJacojQ46YZpkNVhE4sSx\n" +
                "Gf/vdUqh62KP+vwm5cXs/f11WmdVnclv7uR9s3a1GI79lwOJiuw3AIXA3VjR\n" +
                "+AhmeoAFJRfcjfT3hwwkBdu8E3BQ+1bGqfXGhOPYcDTJOO+vMExGSTEk+A9j\n" +
                "DmWnW6snAMd7Bma5xbUaAAAAOAPvCJKYxSQ+SfLb313/tC9N2tGF00x6YJkz\n" +
                "JLqLKVDofMHmUC1f8IJFtQ3cLMDhHVY0VxffLXT1AEffhVpafxBdelL69esq\n" +
                "2zQtDp5l8Hx7D/sU+W3+KmGLnRki72g7gfoQuio+wk8UcHmfwYm7AHvuwsAN\n" +
                "BhgcCgAAACwFgma5xbUCmwwioQYS9REZqU4sfOcCZwgxGwQeisZnaKTEdrCI\n" +
                "/I4zD4IA4AAAAACQUiBvjI1gFe4O/GDPwIoX8YSK/qP3IsMAwvidXclpmlLN\n" +
                "RzPkkfUzRgZw8+AHZxV62TPWhxrZETAuEaahrQ6HViQRAfk60gLvT37iWZrG\n" +
                "BU64272NrJ+UFXrzAEKZ/HK+hIL6yZvYDqIxWBg3Pwt9YxgpOfJ8UeYcrEx3\n" +
                "B1Hkd6QprSOLFCj53zZ++q3SZkWYz28gAA==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(key));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        pIn.close();
        aIn.close();
        bIn.close();

        // created using gosop 430bb02923c123e39815814f6b97a6d501bdde6a
        // ./gosop encrypt --profile=rfc9580 cert.asc < msg.plain > msg.asc
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wYUGIQaz5Iy7+n5O1bg87Cy2PfSolKK6L8cwIPLJnEeZFjMu2xoAfSM/MwQpXahy\n" +
                "Od1pknhDyw3X5EgxQG0EffQCMpaKsNtqvVGYBJ5chuAcV/8gayReP/g6RREGeyj4\n" +
                "Vc2dgJ67/KwaP0Z7k7vExHs79U24DsrU088QbYhk/XLvJHWlXXj90loCCQMMIvmD\n" +
                "KS5f5WYbntB4N+FspsbQ7GN6taOrAqUtEuKWKzrlhZdtg9qGG4RLCvX1vfL0u6NV\n" +
                "Yzk9fGVgty73B8pmyYdefLdWt87ljwr8wGGX/Dl8PSBIE3w=\n" +
                "-----END PGP MESSAGE-----\n";
        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(MSG));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);

        isEquals("PKESK version mismatch",
                PublicKeyEncSessionPacket.VERSION_6, encData.getVersion());
        isEquals("Public Key algorithm mismatch",
                PublicKeyAlgorithmTags.X448, encData.getAlgorithm());
        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyID()); // TODO: getKeyIdentifier()
        isNotNull("Decryption key MUST be identifiable", decryptionKey);
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decryptor = new BcPublicKeyDataDecryptorFactory(privateKey);
        InputStream decrypted = encData.getDataStream(decryptor);
        PGPObjectFactory decFac = new BcPGPObjectFactory(decrypted);
        PGPLiteralData lit = (PGPLiteralData) decFac.nextObject();
        isEncodingEqual("Message plaintext mismatch",
                Strings.toUTF8ByteArray("Hello, World!\n"),
                Streams.readAll(lit.getDataStream()));
    }

    private void decryptMessageUsingSessionKey()
            throws IOException, PGPException
    {
        // created using gosop 430bb02923c123e39815814f6b97a6d501bdde6a
        // ./gosop encrypt --profile=rfc9580 cert.asc < msg.plain > msg.asc
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wYUGIQaz5Iy7+n5O1bg87Cy2PfSolKK6L8cwIPLJnEeZFjMu2xoAfSM/MwQpXahy\n" +
                "Od1pknhDyw3X5EgxQG0EffQCMpaKsNtqvVGYBJ5chuAcV/8gayReP/g6RREGeyj4\n" +
                "Vc2dgJ67/KwaP0Z7k7vExHs79U24DsrU088QbYhk/XLvJHWlXXj90loCCQMMIvmD\n" +
                "KS5f5WYbntB4N+FspsbQ7GN6taOrAqUtEuKWKzrlhZdtg9qGG4RLCvX1vfL0u6NV\n" +
                "Yzk9fGVgty73B8pmyYdefLdWt87ljwr8wGGX/Dl8PSBIE3w=\n" +
                "-----END PGP MESSAGE-----\n";
        String SESSION_KEY = "9:47343387303C170873252051978966871EE2EA0F68D975F061AF022B78B165C1";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(MSG));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPSessionKeyEncryptedData encData = encList.extractSessionKeyEncryptedData();
        SessionKeyDataDecryptorFactory decryptor = new BcSessionKeyDataDecryptorFactory(
                PGPSessionKey.fromAsciiRepresentation(SESSION_KEY));

        InputStream decrypted = encData.getDataStream(decryptor);
        PGPObjectFactory decFac = new BcPGPObjectFactory(decrypted);
        PGPLiteralData lit = (PGPLiteralData) decFac.nextObject();
        isEncodingEqual("Message plaintext mismatch",
                Strings.toUTF8ByteArray("Hello, World!\n"),
                Streams.readAll(lit.getDataStream()));
    }

    public static void main(String[] args)
    {
        runTest(new PGPv6MessageDecryptionTest());
    }
}
