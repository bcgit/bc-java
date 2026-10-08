package org.bouncycastle.oer.its.etsi102941;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

public class AuthorizationValidationResponseCode
    extends ASN1Enumerated
{
    public static final AuthorizationValidationResponseCode ok = new AuthorizationValidationResponseCode(0); //,
    public static final AuthorizationValidationResponseCode cantparse = new AuthorizationValidationResponseCode(1); //, -- valid for any structure
    public static final AuthorizationValidationResponseCode badcontenttype = new AuthorizationValidationResponseCode(2); //, -- not encrypted, not signed, not permissionsverificationrequest
    public static final AuthorizationValidationResponseCode imnottherecipient = new AuthorizationValidationResponseCode(3); //, -- the "recipients" of the outermost encrypted data doesn't include me
    public static final AuthorizationValidationResponseCode unknownencryptionalgorithm = new AuthorizationValidationResponseCode(4); //, -- either kexalg or contentencryptionalgorithm
    public static final AuthorizationValidationResponseCode decryptionfailed = new AuthorizationValidationResponseCode(5); //, -- works for ECIES-HMAC and AES-CCM
    public static final AuthorizationValidationResponseCode invalidaa = new AuthorizationValidationResponseCode(6); //, -- the AA certificate presented is invalid/revoked/whatever
    public static final AuthorizationValidationResponseCode invalidaasignature = new AuthorizationValidationResponseCode(7); //, -- the AA certificate presented can't validate the request signature
    public static final AuthorizationValidationResponseCode wrongea = new AuthorizationValidationResponseCode(8); //, -- the encrypted signature doesn't designate me as the EA
    public static final AuthorizationValidationResponseCode unknownits = new AuthorizationValidationResponseCode(9); //, -- can't retrieve the EC/ITS in my DB
    public static final AuthorizationValidationResponseCode invalidsignature = new AuthorizationValidationResponseCode(10); //, -- signature verification of the request by the EC fails
    public static final AuthorizationValidationResponseCode invalidencryptionkey = new AuthorizationValidationResponseCode(11); //, -- signature is good, but the responseEncryptionKey is bad
    public static final AuthorizationValidationResponseCode deniedpermissions = new AuthorizationValidationResponseCode(12); //, -- requested permissions not granted
    public static final AuthorizationValidationResponseCode deniedtoomanycerts = new AuthorizationValidationResponseCode(13); //, -- parallel limit
    public static final AuthorizationValidationResponseCode deniedrequest = new AuthorizationValidationResponseCode(14); //, -- any other reason?

    /**
     * The constants indexed by value, for getInstance to return the shared instance. An entry
     * can be null, should the value set ever become sparse, and the lookup checks for that.
     */
    private static final AuthorizationValidationResponseCode[] VALUES = new AuthorizationValidationResponseCode[15];

    static
    {
        VALUES[0] = ok;
        VALUES[1] = cantparse;
        VALUES[2] = badcontenttype;
        VALUES[3] = imnottherecipient;
        VALUES[4] = unknownencryptionalgorithm;
        VALUES[5] = decryptionfailed;
        VALUES[6] = invalidaa;
        VALUES[7] = invalidaasignature;
        VALUES[8] = wrongea;
        VALUES[9] = unknownits;
        VALUES[10] = invalidsignature;
        VALUES[11] = invalidencryptionkey;
        VALUES[12] = deniedpermissions;
        VALUES[13] = deniedtoomanycerts;
        VALUES[14] = deniedrequest;
    }

    public AuthorizationValidationResponseCode(int value)
    {
        super(value);
        assertValues();
    }

    public AuthorizationValidationResponseCode(BigInteger value)
    {
        super(value);
        assertValues();
    }

    public AuthorizationValidationResponseCode(byte[] contents)
    {
        super(contents);
        assertValues();
    }



    protected void assertValues()
    {
        BigInteger value = getValue();
        // intValue() truncates, so a value past the int range has to be rejected before it is consulted
        if (value.signum() < 0 || value.bitLength() > 31 || value.intValue() > 14)
        {
            throw new IllegalArgumentException("invalid enumeration value " + value);
        }
    }

    public static AuthorizationValidationResponseCode getInstance(Object o)
    {
        if (o instanceof AuthorizationValidationResponseCode)
        {
            return (AuthorizationValidationResponseCode)o;
        }

        if (o != null)
        {
            return getInstance(ASN1Enumerated.getInstance(o));
        }

        return null;
    }

    private static AuthorizationValidationResponseCode getInstance(ASN1Enumerated value)
    {
        BigInteger v = value.getValue();
        // the value must index the table: non-negative and within the int range before intValue() is
        // trusted, within the table, and held by a constant (the set may one day be sparse)
        if (v.signum() >= 0 && v.bitLength() < 31)
        {
            int index = v.intValue();
            if (index < VALUES.length)
            {
                AuthorizationValidationResponseCode constant = VALUES[index];
                if (constant != null)
                {
                    return constant;
                }
            }
        }
        throw new IllegalArgumentException("invalid enumeration value " + v);
    }

}
