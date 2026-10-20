#[cfg(windows)]
pub fn local_iso8601() -> String {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct WindowsSystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct TimeZoneInformation {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: WindowsSystemTime,
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: WindowsSystemTime,
        daylight_bias: i32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLocalTime(system_time: *mut WindowsSystemTime);
        fn GetTimeZoneInformation(time_zone_information: *mut TimeZoneInformation) -> u32;
    }

    const TIME_ZONE_ID_STANDARD: u32 = 1;
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

    let mut local = WindowsSystemTime::default();
    let mut timezone = TimeZoneInformation::default();
    unsafe {
        GetLocalTime(&mut local);
    }
    let timezone_id = unsafe { GetTimeZoneInformation(&mut timezone) };
    let effective_bias = match timezone_id {
        TIME_ZONE_ID_STANDARD => timezone.bias + timezone.standard_bias,
        TIME_ZONE_ID_DAYLIGHT => timezone.bias + timezone.daylight_bias,
        _ => timezone.bias,
    };
    let offset_minutes = -effective_bias;
    format_timestamp(
        i32::from(local.year),
        u32::from(local.month),
        u32::from(local.day),
        u32::from(local.hour),
        u32::from(local.minute),
        u32::from(local.second),
        offset_minutes,
    )
}

#[cfg(not(windows))]
pub fn local_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (seconds_of_day / 3_600) as u32;
    let minute = ((seconds_of_day % 3_600) / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    format_timestamp(year, month, day, hour, minute, second, 0)
}

fn format_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    offset_minutes: i32,
) -> String {
    let sign = if offset_minutes >= 0 { '+' } else { '-' };
    let absolute_offset = offset_minutes.abs();
    let offset_hours = absolute_offset / 60;
    let offset_remainder = absolute_offset % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{sign}{offset_hours:02}:{offset_remainder:02}"
    )
}

#[cfg(not(windows))]
fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}
