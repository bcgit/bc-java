package com.github.gv2011.bcasn.crypto.params;

import java.security.SecureRandom;

import com.github.gv2011.bcasn.crypto.KeyGenerationParameters;

public class GOST3410KeyGenerationParameters
        extends KeyGenerationParameters
{
        private GOST3410Parameters    params;

        public GOST3410KeyGenerationParameters(
            SecureRandom    random,
            GOST3410Parameters   params)
        {
            super(random, params.getP().bitLength() - 1);

            this.params = params;
        }

        public GOST3410Parameters getParameters()
        {
            return params;
        }
}
