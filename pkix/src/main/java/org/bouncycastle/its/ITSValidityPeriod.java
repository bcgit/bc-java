package org.bouncycastle.its;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.Duration;
import org.bouncycastle.oer.its.ValidityPeriod;

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
            return new ITSValidityPeriod(startDate, years, Unit.years);
        }

        public ITSValidityPeriod plusSixtyHours(int periods)
        {
            return new ITSValidityPeriod(startDate, periods, Unit.sixtyHours);
        }
    }

    public static Builder from(Date startDate)
    {
        return new Builder(startDate);
    }

    private final long startDate;
    private final int duration;
    private final Unit timeUnit;

    public ITSValidityPeriod(ValidityPeriod validityPeriod)
    {
        this.startDate = validityPeriod.getTime32().getValue();
        Duration duration = validityPeriod.getDuration();
        this.duration = duration.getValue();
        this.timeUnit = Unit.values()[duration.getTag()];
    }

    ITSValidityPeriod(long startDate, int duration, Unit timeUnit)
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
            .setTime32(new ASN1Integer(startDate / 1000))
            .setDuration(new Duration(duration, timeUnit.unitTag)).createValidityPeriod();
    }
}
