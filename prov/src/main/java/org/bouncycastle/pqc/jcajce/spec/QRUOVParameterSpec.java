package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.pqc.crypto.qruov.QRUOVParameters;
import org.bouncycastle.util.Strings;

public class QRUOVParameterSpec
    implements AlgorithmParameterSpec
{
    public static final QRUOVParameterSpec qruov1q127L3v156m54 = new QRUOVParameterSpec(QRUOVParameters.qruov_1_q127_L3_v156_m54_shake);
    public static final QRUOVParameterSpec qruov1q31L3v165m60 = new QRUOVParameterSpec(QRUOVParameters.qruov_1_q31_L3_v165_m60_shake);
    public static final QRUOVParameterSpec qruov1q31L10v600m70 = new QRUOVParameterSpec(QRUOVParameters.qruov_1_q31_L10_v600_m70_shake);
    public static final QRUOVParameterSpec qruov1q7L10v740m100 = new QRUOVParameterSpec(QRUOVParameters.qruov_1_q7_L10_v740_m100_shake);
    public static final QRUOVParameterSpec qruov3q127L3v228m78 = new QRUOVParameterSpec(QRUOVParameters.qruov_3_q127_L3_v228_m78_shake);
    public static final QRUOVParameterSpec qruov3q31L3v246m87 = new QRUOVParameterSpec(QRUOVParameters.qruov_3_q31_L3_v246_m87_shake);
    public static final QRUOVParameterSpec qruov3q31L10v890m100 = new QRUOVParameterSpec(QRUOVParameters.qruov_3_q31_L10_v890_m100_shake);
    public static final QRUOVParameterSpec qruov3q7L10v1100m140 = new QRUOVParameterSpec(QRUOVParameters.qruov_3_q7_L10_v1100_m140_shake);
    public static final QRUOVParameterSpec qruov5q127L3v306m105 = new QRUOVParameterSpec(QRUOVParameters.qruov_5_q127_L3_v306_m105_shake);
    public static final QRUOVParameterSpec qruov5q31L3v324m114 = new QRUOVParameterSpec(QRUOVParameters.qruov_5_q31_L3_v324_m114_shake);
    public static final QRUOVParameterSpec qruov5q31L10v1120m120 = new QRUOVParameterSpec(QRUOVParameters.qruov_5_q31_L10_v1120_m120_shake);
    public static final QRUOVParameterSpec qruov5q7L10v1490m190 = new QRUOVParameterSpec(QRUOVParameters.qruov_5_q7_L10_v1490_m190_shake);

    private static final Map parameters = new HashMap();

    static
    {
        parameters.put("qruov1q127l3v156m54", qruov1q127L3v156m54);
        parameters.put("qruov1q31l3v165m60", qruov1q31L3v165m60);
        parameters.put("qruov1q31l10v600m70", qruov1q31L10v600m70);
        parameters.put("qruov1q7l10v740m100", qruov1q7L10v740m100);
        parameters.put("qruov3q127l3v228m78", qruov3q127L3v228m78);
        parameters.put("qruov3q31l3v246m87", qruov3q31L3v246m87);
        parameters.put("qruov3q31l10v890m100", qruov3q31L10v890m100);
        parameters.put("qruov3q7l10v1100m140", qruov3q7L10v1100m140);
        parameters.put("qruov5q127l3v306m105", qruov5q127L3v306m105);
        parameters.put("qruov5q31l3v324m114", qruov5q31L3v324m114);
        parameters.put("qruov5q31l10v1120m120", qruov5q31L10v1120m120);
        parameters.put("qruov5q7l10v1490m190", qruov5q7L10v1490m190);
    }

    private final String name;

    private QRUOVParameterSpec(QRUOVParameters parameters)
    {
        // strip the "-shake"/"-aes" suffix used by the lightweight engine; the JCA
        // surface only exposes the canonical (SHAKE-PRG) variants.
        String raw = parameters.getName();
        int dash = raw.indexOf('-');
        this.name = dash > 0 ? raw.substring(0, dash) : raw;
    }

    public String getName()
    {
        return name;
    }

    public static QRUOVParameterSpec fromName(String name)
    {
        return (QRUOVParameterSpec)parameters.get(Strings.toLowerCase(name));
    }
}
