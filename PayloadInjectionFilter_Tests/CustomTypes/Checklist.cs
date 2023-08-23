namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class Checklist
    {
        public int ChecklistId { get; set; }
        public int ServiceId { get; set; }
        public string ChecklistItem { get; set; }
        public string Link { get; set; }
        public string LinkName { get; set; }
        public int SortValue { get; set; }
        public int? CreatedBy { get; set; }
        public int? ChangedBy { get; set; }
    }
}
