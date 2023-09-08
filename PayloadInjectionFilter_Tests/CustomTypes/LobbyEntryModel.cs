namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class LobbyCheckInDto
    {
        public int LocationId { get; set; }
        public int LobbySourceId { get; set; }
        public string TimeZoneId { get; set; }
        public string AccountNumber { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string DateOfBirth { get; set; }
        public string Notes { get; set; }
        public string PhoneNumber { get; set; }
        public string EmailAddress { get; set; }
        public int PreferredLanguage { get; set; }
        public bool RecieveTextMessage { get; set; }
        public List<int> ServiceRequested { get; set; }
        public Dictionary<string, string> CustomFieldValues { get; set; }
        public long? AppointmentId { get; set; }
        public int? UserRequested { get; set; }
        public int? GroupRequested { get; set; }
    }
}
