package org.bouncycastle.jce.interfaces;

import org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

public interface GOST3410Params
{

    public String getPublicKeyParamSetOID();

    public String getDigestParamSetOID();

    public String getEncryptionParamSetOID();
    
    public GOST3410PublicKeyParameterSetSpec getPublicKeyParameters();
}
