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

    private AuthorizationValidationResponseCode(ASN1Enumerated instance)
    {
        super(instance.getValue());
        assertValues();
    }


    protected void assertValues()
    {
        if (getValue().intValue() < 0 || getValue().intValue() > 14)
        {
            throw new IllegalArgumentException("invalid enumeration value " + getValue());
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
            return new AuthorizationValidationResponseCode(ASN1Enumerated.getInstance(o));
        }

        return null;
    }

}
