use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

const CANONICAL_UTC: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

pub fn canonical_now() -> Result<String, String> {
    canonical(OffsetDateTime::now_utc())
}

pub fn canonical(value: OffsetDateTime) -> Result<String, String> {
    value
        .format(CANONICAL_UTC)
        .map_err(|error| error.to_string())
}

pub fn epoch_seconds() -> Result<u64, String> {
    OffsetDateTime::now_utc()
        .unix_timestamp()
        .try_into()
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}
