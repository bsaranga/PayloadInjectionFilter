namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class SortOrderViewModel
    {
        public bool ApplyForAllLocations { get; set; }
        public bool IsCategorySortOrderType { get; set; }
        public int[] LocationIds { get; set; }
        public int ServiceCategoryId { get; set; }
        public List<ServiceSortOrder> ServiceSortOrderList { get; set; }
    }

    public class ServiceSortOrder
    {
        public int Id { get; set; }
        public string ServiceName { get; set; }
        public int SortOrder { get; set; }
        public bool IsCategorySortOrderType { get; set; }
        public bool OptIn { get; set; }
        public DateTime? LastUpdatedTime { get; set; }
        public string ServiceCode { get; set; }
    }
}
