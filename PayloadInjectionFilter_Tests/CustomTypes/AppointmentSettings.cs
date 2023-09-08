namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class ServiceAppointmentSetting
    {
        public int Id { get; set; }
        public int ServiceId { get; set; }
        public int LocationId { get; set; }
        public int DurationInMins { get; set; }
        public bool? InPersonAppointment { get; set; }
        public bool? PhoneAppointment { get; set; }
        public bool? VirtualAppointment { get; set; }
        public bool ShowInWidget { get; set; }
        public bool AllowModifyWidget { get; set; }
        public bool RequireComments { get; set; }
        public string AdditoinalInformation { get; set; }
        public List<DynamicLocalizedText> LocalizedCommentsList { get; set; }
        public bool ApplyForAllLocations { get; set; }
        public int[] LocationIds { get; set; }
    }

    public class DynamicLocalizedText
    {
        public int LocalizedTextId { get; set; }
        public int LanguageId { get; set; }
        public int LocalizedFieldId { get; set; }
        public Guid LocalizedRowId { get; set; }
        public string Text { get; set; }

    }
}
