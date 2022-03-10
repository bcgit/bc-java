package org.bouncycastle.oer.its.etsi102941;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

public class AuthorizationResponseCode
    extends ASN1Enumerated
{


    public static final AuthorizationResponseCode ok = new AuthorizationResponseCode(0);
    //-- ITS->AA
    public static final AuthorizationResponseCode its_aa_cantparse = new AuthorizationResponseCode(1); // , -- valid for any structure
    public static final AuthorizationResponseCode its_aa_badcontenttype = new AuthorizationResponseCode(2);  //, -- not encrypted, not signed, not authorizationrequest
    public static final AuthorizationResponseCode its_aa_imnottherecipient = new AuthorizationResponseCode(3); //, -- the "recipients" of the outermost encrypted data doesn't include me
    public static final AuthorizationResponseCode its_aa_unknownencryptionalgorithm = new AuthorizationResponseCode(4); //, -- either kexalg or contentencryptionalgorithm
    public static final AuthorizationResponseCode its_aa_decryptionfailed = new AuthorizationResponseCode(5); //, -- works for ECIES-HMAC and AES-CCM
    public static final AuthorizationResponseCode its_aa_keysdontmatch = new AuthorizationResponseCode(6); // -- HMAC keyTag verification fails
    public static final AuthorizationResponseCode its_aa_incompleterequest = new AuthorizationResponseCode(7); //, -- some elements are missing
    public static final AuthorizationResponseCode its_aa_invalidencryptionkey = new AuthorizationResponseCode(8); //, -- the responseEncryptionKey is bad
    public static final AuthorizationResponseCode its_aa_outofsyncrequest = new AuthorizationResponseCode(9); //, -- signingTime is outside acceptable limits
    public static final AuthorizationResponseCode its_aa_unknownea = new AuthorizationResponseCode(10); //, -- the EA identified by eaId is unknown to me
    public static final AuthorizationResponseCode its_aa_invalidea = new AuthorizationResponseCode(11); //, -- the EA certificate is revoked
    public static final AuthorizationResponseCode its_aa_deniedpermissions = new AuthorizationResponseCode(12); //, -- I, the AA, deny the requested permissions
    // -- AA->EA
    public static final AuthorizationResponseCode aa_ea_cantreachea = new AuthorizationResponseCode(13); //, -- the EA is unreachable (network error?)
    // -- EA->AA
    public static final AuthorizationResponseCode ea_aa_cantparse = new AuthorizationResponseCode(14); //, -- valid for any structure
    public static final AuthorizationResponseCode ea_aa_badcontenttype = new AuthorizationResponseCode(15); //, -- not encrypted, not signed, not authorizationrequest
    public static final AuthorizationResponseCode ea_aa_imnottherecipient = new AuthorizationResponseCode(16); //, -- the "recipients" of the outermost encrypted data doesn't include me
    public static final AuthorizationResponseCode ea_aa_unknownencryptionalgorithm = new AuthorizationResponseCode(17); //, -- either kexalg or contentencryptionalgorithm
    public static final AuthorizationResponseCode ea_aa_decryptionfailed = new AuthorizationResponseCode(18); //, -- works for ECIES-HMAC and AES-CCM
    /// -- TODO: to be continued...
    public static final AuthorizationResponseCode invalidaa = new AuthorizationResponseCode(19); //, -- the AA certificate presented is invalid/revoked/whatever
    public static final AuthorizationResponseCode invalidaasignature = new AuthorizationResponseCode(20); //, -- the AA certificate presented can't validate the request signature
    public static final AuthorizationResponseCode wrongea = new AuthorizationResponseCode(21); //, -- the encrypted signature doesn't designate me as the EA
    public static final AuthorizationResponseCode unknownits = new AuthorizationResponseCode(22); //, -- can't retrieve the EC/ITS in my DB
    public static final AuthorizationResponseCode invalidsignature = new AuthorizationResponseCode(23); //, -- signature verification of the request by the EC fails
    public static final AuthorizationResponseCode invalidencryptionkey = new AuthorizationResponseCode(24); //, -- signature is good, but the key is bad
    public static final AuthorizationResponseCode deniedpermissions = new AuthorizationResponseCode(25); //, -- permissions not granted
    public static final AuthorizationResponseCode deniedtoomanycerts = new AuthorizationResponseCode(26); //, -- parallel limit

    public AuthorizationResponseCode(int value)
    {
        super(value);
        assertValues();
    }

    public AuthorizationResponseCode(BigInteger value)
    {
        super(value);
        assertValues();
    }

    public AuthorizationResponseCode(byte[] contents)
    {
        super(contents);
        assertValues();
    }

    protected void assertValues()
    {
        if (getValue().intValue() < 0 || getValue().intValue() > 26)
        {
            throw new IllegalArgumentException("invalid enumeration value " + getValue());
        }
    }


    private AuthorizationResponseCode(ASN1Enumerated instance)
    {
        super(instance.getValue());
        assertValues();
    }

    public static AuthorizationResponseCode getInstance(Object o)
    {
        if (o instanceof AuthorizationResponseCode)
        {
            return (AuthorizationResponseCode)o;
        }

        if (o != null)
        {
            return new AuthorizationResponseCode(ASN1Enumerated.getInstance(o));
        }

        return null;
    }

}
