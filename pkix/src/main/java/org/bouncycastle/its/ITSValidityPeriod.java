package org.bouncycastle.its;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Duration;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT16;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ValidityPeriod;

public class ITSValidityPeriod
{
    public enum Unit
    {
        microseconds(Duration.microseconds),
        milliseconds(Duration.milliseconds),
        seconds(Duration.seconds),
        minutes(Duration.minutes),
        hours(Duration.hours),
        sixtyHours(Duration.sixtyHours),
        years(Duration.years);

        private final int unitTag;

        Unit(int unitTag)
        {
            this.unitTag = unitTag;
        }
    }

    public static class Builder
    {
        private final long startDate;

        Builder(Date startDate)
        {
            this.startDate = startDate.getTime();
        }

        public ITSValidityPeriod plusYears(int years)
        {
            return new ITSValidityPeriod(startDate, UINT16.valueOf(years), Unit.years);
        }

        public ITSValidityPeriod plusSixtyHours(int periods)
        {
            return new ITSValidityPeriod(startDate, UINT16.valueOf(periods), Unit.sixtyHours);
        }
    }

    public static Builder from(Date startDate)
    {
        return new Builder(startDate);
    }

    private final long startDate;
    private final UINT16 duration;
    private final Unit timeUnit;

    public ITSValidityPeriod(ValidityPeriod validityPeriod)
    {
        this.startDate = validityPeriod.getStart().getValue().longValue();
        Duration duration = validityPeriod.getDuration();
        this.duration = duration.getDuration();
        this.timeUnit = Unit.values()[duration.getChoice()];
    }

    ITSValidityPeriod(long startDate, UINT16 duration, Unit timeUnit)
    {
        this.startDate = startDate;
        this.duration = duration;
        this.timeUnit = timeUnit;
    }

    public Date getStartDate()
    {
        return new Date(startDate);
    }

    public ValidityPeriod toASN1Structure()
    {
        return ValidityPeriod.builder()
            .setStart(new Time32(startDate / 1000))
            .setDuration(new Duration(timeUnit.unitTag, duration)).createValidityPeriod();
    }
}
