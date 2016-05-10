package com.github.gv2011.bcasn.crypto.params;

import java.security.SecureRandom;

import com.github.gv2011.bcasn.crypto.KeyGenerationParameters;

public class CramerShoupKeyGenerationParameters
	extends KeyGenerationParameters
{

	private CramerShoupParameters params;

	public CramerShoupKeyGenerationParameters(SecureRandom random, CramerShoupParameters params)
	{
		super(random, getStrength(params));

		this.params = params;
	}

	public CramerShoupParameters getParameters()
	{
		return params;
	}

	static int getStrength(CramerShoupParameters params)
	{
		return params.getP().bitLength();
	}
}
