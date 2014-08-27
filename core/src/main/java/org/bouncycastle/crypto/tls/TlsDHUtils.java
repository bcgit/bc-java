package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

public class TlsDHUtils
{
    static final BigInteger TWO = BigInteger.valueOf(2);

    public static final Integer EXT_negotiated_ff_dhe_groups = Integers.valueOf(ExtensionType.negotiated_ff_dhe_groups);

    /*
     * TODO[draft-ietf-tls-negotiated-ff-dhe-01] Move these groups to DHStandardGroups once reaches RFC
     */
    private static BigInteger fromHex(String hex)
    {
        return new BigInteger(1, Hex.decode(hex));
    }

    private static DHParameters fromSafeP(String hexP)
    {
        BigInteger p = fromHex(hexP), q = p.shiftRight(1);
        return new DHParameters(p, TWO, q);
    }

    private static final String draft_ffdhe2432_p =
          "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
        + "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
        + "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
        + "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        + "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
        + "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
        + "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
        + "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        + "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
        + "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
        + "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
        + "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        + "AEFE13098533C8B3FFFFFFFFFFFFFFFF";
    static final DHParameters draft_ffdhe2432 = fromSafeP(draft_ffdhe2432_p);

    private static final String draft_ffdhe3072_p =
          "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
        + "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
        + "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
        + "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        + "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
        + "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
        + "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
        + "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        + "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
        + "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
        + "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
        + "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        + "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
        + "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
        + "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
        + "3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF";
    static final DHParameters draft_ffdhe3072 = fromSafeP(draft_ffdhe3072_p);

    private static final String draft_ffdhe4096_p =
          "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
        + "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
        + "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
        + "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        + "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
        + "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
        + "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
        + "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        + "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
        + "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
        + "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
        + "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        + "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
        + "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
        + "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
        + "3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
        + "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"
        + "87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"
        + "A907600A918130C46DC778F971AD0038092999A333CB8B7A"
        + "1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
        + "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6A"
        + "FFFFFFFFFFFFFFFF";
    static final DHParameters draft_ffdhe4096 = fromSafeP(draft_ffdhe4096_p);

    private static final String draft_ffdhe6144_p =
          "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
        + "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
        + "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
        + "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        + "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
        + "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
        + "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
        + "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        + "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
        + "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
        + "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
        + "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        + "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
        + "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
        + "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
        + "3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
        + "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"
        + "87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"
        + "A907600A918130C46DC778F971AD0038092999A333CB8B7A"
        + "1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
        + "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902"
        + "0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6"
        + "3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A"
        + "CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"
        + "A52471F7A9A96910B855322EDB6340D8A00EF092350511E3"
        + "0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4"
        + "763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6"
        + "B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"
        + "D72B03746AE77F5E62292C311562A846505DC82DB854338A"
        + "E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04"
        + "5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1"
        + "A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF";
    static final DHParameters draft_ffdhe6144 = fromSafeP(draft_ffdhe6144_p);

    private static final String draft_ffdhe8192_p =
          "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
        + "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
        + "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
        + "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        + "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
        + "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
        + "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
        + "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        + "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
        + "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
        + "886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238"
        + "61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        + "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3"
        + "64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D"
        + "ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF"
        + "3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
        + "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004"
        + "87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832"
        + "A907600A918130C46DC778F971AD0038092999A333CB8B7A"
        + "1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
        + "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902"
        + "0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6"
        + "3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A"
        + "CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477"
        + "A52471F7A9A96910B855322EDB6340D8A00EF092350511E3"
        + "0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4"
        + "763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6"
        + "B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C"
        + "D72B03746AE77F5E62292C311562A846505DC82DB854338A"
        + "E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04"
        + "5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1"
        + "A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C838"
        + "1E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E"
        + "0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665"
        + "CB2C0F1CC01BD70229388839D2AF05E454504AC78B758282"
        + "2846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022"
        + "BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C"
        + "51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9"
        + "D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA457"
        + "1EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30"
        + "FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D"
        + "97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88C"
        + "D68C8BB7C5C6424CFFFFFFFFFFFFFFFF";
    static final DHParameters draft_ffdhe8192 = fromSafeP(draft_ffdhe8192_p);

    
    public static void addNegotiatedDHEGroupsClientExtension(Hashtable extensions, short[] dheGroups)
        throws IOException
    {
        extensions.put(EXT_negotiated_ff_dhe_groups, createNegotiatedDHEGroupsClientExtension(dheGroups));
    }

    public static void addNegotiatedDHEGroupsServerExtension(Hashtable extensions, short dheGroup)
        throws IOException
    {
        extensions.put(EXT_negotiated_ff_dhe_groups, createNegotiatedDHEGroupsServerExtension(dheGroup));
    }

    public static short[] getNegotiatedDHEGroupsClientExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_negotiated_ff_dhe_groups);
        return extensionData == null ? null : readNegotiatedDHEGroupsClientExtension(extensionData);
    }

    public static short getNegotiatedDHEGroupsServerExtension(Hashtable extensions) throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_negotiated_ff_dhe_groups);
        return extensionData == null ? -1 : readNegotiatedDHEGroupsServerExtension(extensionData);
    }

    public static byte[] createNegotiatedDHEGroupsClientExtension(short[] dheGroups) throws IOException
    {
        if (dheGroups == null || dheGroups.length < 1 || dheGroups.length > 255)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return TlsUtils.encodeUint8ArrayWithUint8Length(dheGroups);
    }

    public static byte[] createNegotiatedDHEGroupsServerExtension(short dheGroup) throws IOException
    {
        TlsUtils.checkUint8(dheGroup);

        byte[] extensionData = new byte[1];
        TlsUtils.writeUint8(dheGroup, extensionData, 0);
        return extensionData;
    }

    public static short[] readNegotiatedDHEGroupsClientExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

        short length = TlsUtils.readUint8(buf);
        if (length < 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        short[] dheGroups = TlsUtils.readUint8Array(length, buf);

        TlsProtocol.assertEmpty(buf);

        return dheGroups;
    }

    public static short readNegotiatedDHEGroupsServerExtension(byte[] extensionData) throws IOException
    {
        if (extensionData == null)
        {
            throw new IllegalArgumentException("'extensionData' cannot be null");
        }

        if (extensionData.length != 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return TlsUtils.readUint8(extensionData, 0);
    }

    public static DHParameters getParametersForDHEGroup(short dheGroup)
    {
        switch (dheGroup)
        {
        case FiniteFieldDHEGroup.ffdhe2432:
            return draft_ffdhe2432;
        case FiniteFieldDHEGroup.ffdhe3072:
            return draft_ffdhe3072;
        case FiniteFieldDHEGroup.ffdhe4096:
            return draft_ffdhe4096;
        case FiniteFieldDHEGroup.ffdhe6144:
            return draft_ffdhe6144;
        case FiniteFieldDHEGroup.ffdhe8192:
            return draft_ffdhe8192;
        default:
            return null;
        }
    }

    public static boolean containsDHECipherSuites(int[] cipherSuites)
    {
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            if (isDHECipherSuite(cipherSuites[i]))
            {
                return true;
            }
        }
        return false;
    }

    public static boolean isDHECipherSuite(int cipherSuite)
    {
        switch (cipherSuite)
        {
        /*
         * RFC 2246
         */
        case CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:

        /*
         * RFC 3268
         */
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:

        /*
         * RFC 5932
         */
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:

        /*
         * RFC 4162
         */
        case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
        case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:

        /*
         * RFC 4279
         */
        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:

        /*
         * RFC 4785
         */
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:

        /*
         * RFC 5246
         */
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:

        /*
         * RFC 5288
         */
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:

        /*
         * RFC 5487
         */
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:

        /*
         * RFC 6367
         */
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:

        /*
         * RFC 6655
         */
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:

        /*
         * draft-agl-tls-chacha20poly1305-04
         */
        case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:

        /*
         * draft-josefsson-salsa20-tls-04
         */
        case CipherSuite.TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1:
        case CipherSuite.TLS_DHE_PSK_WITH_SALSA20_SHA1:
        case CipherSuite.TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1:
        case CipherSuite.TLS_DHE_RSA_WITH_SALSA20_SHA1:

            return true;

        default:
            return false;
        }
    }

    public static boolean areCompatibleParameters(DHParameters a, DHParameters b)
    {
        return a.getP().equals(b.getP()) && a.getG().equals(b.getG());
    }

    public static byte[] calculateDHBasicAgreement(DHPublicKeyParameters publicKey, DHPrivateKeyParameters privateKey)
    {
        DHBasicAgreement basicAgreement = new DHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(publicKey);

        /*
         * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it is
         * used as the pre_master_secret.
         */
        return BigIntegers.asUnsignedByteArray(agreementValue);
    }

    public static AsymmetricCipherKeyPair generateDHKeyPair(SecureRandom random, DHParameters dhParams)
    {
        DHBasicKeyPairGenerator dhGen = new DHBasicKeyPairGenerator();
        dhGen.init(new DHKeyGenerationParameters(random, dhParams));
        return dhGen.generateKeyPair();
    }

    public static DHPrivateKeyParameters generateEphemeralClientKeyExchange(SecureRandom random, DHParameters dhParams,
        OutputStream output) throws IOException
    {
        AsymmetricCipherKeyPair kp = generateDHKeyPair(random, dhParams);

        DHPublicKeyParameters dhPublic = (DHPublicKeyParameters) kp.getPublic();
        writeDHParameter(dhPublic.getY(), output);

        return (DHPrivateKeyParameters) kp.getPrivate();
    }

    public static DHPrivateKeyParameters generateEphemeralServerKeyExchange(SecureRandom random, DHParameters dhParams,
        OutputStream output) throws IOException
    {
        AsymmetricCipherKeyPair kp = generateDHKeyPair(random, dhParams);

        DHPublicKeyParameters dhPublic = (DHPublicKeyParameters)kp.getPublic();
        new ServerDHParams(dhPublic).encode(output);

        return (DHPrivateKeyParameters)kp.getPrivate();
    }

    public static DHPublicKeyParameters validateDHPublicKey(DHPublicKeyParameters key) throws IOException
    {
        BigInteger Y = key.getY();
        DHParameters params = key.getParameters();
        BigInteger p = params.getP();
        BigInteger g = params.getG();

        if (!p.isProbablePrime(2))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        if (g.compareTo(TWO) < 0 || g.compareTo(p.subtract(TWO)) > 0)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        if (Y.compareTo(TWO) < 0 || Y.compareTo(p.subtract(TWO)) > 0)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        // TODO See RFC 2631 for more discussion of Diffie-Hellman validation

        return key;
    }

    public static BigInteger readDHParameter(InputStream input) throws IOException
    {
        return new BigInteger(1, TlsUtils.readOpaque16(input));
    }

    public static void writeDHParameter(BigInteger x, OutputStream output) throws IOException
    {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(x), output);
    }
}
