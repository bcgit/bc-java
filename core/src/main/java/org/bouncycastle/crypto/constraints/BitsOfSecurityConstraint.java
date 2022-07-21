package org.bouncycastle.crypto.constraints;

import org.bouncycastle.crypto.CryptoService;
import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicesConstraints;

public class BitsOfSecurityConstraint
    implements CryptoServicesConstraints
{
    private final int requiredBitsOfSecurity;

    public BitsOfSecurityConstraint(int requiredBitsOfSecurity)
    {
        this.requiredBitsOfSecurity = requiredBitsOfSecurity;
    }

    public void check(CryptoService service)
    {
        if (service.bitsOfSecurity() < requiredBitsOfSecurity)
        {
            throw new CryptoServiceConstraintsException("service does not provide " + requiredBitsOfSecurity + " bits of security only " + service.bitsOfSecurity());
        }
    }
}
