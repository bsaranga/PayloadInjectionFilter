namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class LocationHolidayDetail
    {
        public LocationHoliday LocationHoliday { get; set; }
        public List<LocationHoliday> SubLocationHolidays { get; set; }
        public HolidayDetailsChangeTracking HolidaysChangetracing { get; set; }
    }

    public class LocationHoliday
    {
        public int Id { get; set; }
        public int? HolidayId { get; set; }
        public string? HolidayName { get; set; }
        public int LocationId { get; set; }
        public DateTime? Date { get; set; }
        public DateTime? StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public bool IsAllDay { get; set; }
        public bool BlackOutDay { get; set; }
        public bool OptInAtSubLocations { get; set; }
        public int?[] LocationIds { get; set; }
    };

    public class HolidayDetailsChangeTracking
    {
        public bool IsBlackOutChanged { get; set; } = false;
        public bool IsAllDayChanged { get; set; } = false;
        public bool IsOptInChanged { get; set; } = false;
        public bool IsStartTimeChanged { get; set; } = false;
        public bool IsEndTimeChanged { get; set; } = false;
    }
}
