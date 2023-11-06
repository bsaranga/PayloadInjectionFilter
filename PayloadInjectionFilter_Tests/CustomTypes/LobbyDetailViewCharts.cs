using PayloadInjectionFilter_Tests.CustomTypes.Meta;

namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class DetailsViewChartDataRequest
    {
        public DateTime startDate;
        public DateTime endDate;
        public DetailsViewFilterTemplateResponse template;
    }
    public class DetailsViewFilterTemplateResponse
    {
        public int TemplateId { get; set; }
        public bool IsDefault { get; set; }
        public string TemplateName { get; set; }
        public bool AllLocations { get; set; }
        public bool AllAssistTypes { get; set; }
        public bool AllCategories { get; set; }
        public bool AllDays { get; set; }
        public bool AllServices { get; set; }
        public bool AllRequestedStaff { get; set; }
        public bool AllAssistedBy { get; set; }
        public bool AllSupervisors { get; set; }
        public bool AllStatuses { get; set; }
        public ActiveFilters ActiveFilters { get; set; }
        public DetailsViewFilterTemplateResponse()
        {
            ActiveFilters = new ActiveFilters();
        }
    }
}

namespace PayloadInjectionFilter_Tests.CustomTypes.Meta
{
    public class ActiveFilters
    {
        public IList<DetailViewLocationApiResponseModel> Locations = new List<DetailViewLocationApiResponseModel>();
        public IList<DetailViewAssistTypeApiResponseModel> AssistTypes = new List<DetailViewAssistTypeApiResponseModel>();
        public IList<DetailViewCategoryApiResponseModel> Categories = new List<DetailViewCategoryApiResponseModel>();
        public IList<DetailViewDayOfWeekApiResponseModel> DaysOfWeek = new List<DetailViewDayOfWeekApiResponseModel>();
        public IList<DetailViewDefaultViewApiResponseModel> DefaultViews = new List<DetailViewDefaultViewApiResponseModel>();
        public IList<DetailViewSearchTermApiResponseModel> SearchTerms = new List<DetailViewSearchTermApiResponseModel>();
        public IList<DetailViewServiceApiResponseModel> Services = new List<DetailViewServiceApiResponseModel>();
        public IList<DetailViewStaffApiResponseModel> RequestedStaff = new List<DetailViewStaffApiResponseModel>();
        public IList<DetailViewStaffApiResponseModel> AssistedBy = new List<DetailViewStaffApiResponseModel>();
        public IList<DetailViewStaffApiResponseModel> Supervisors = new List<DetailViewStaffApiResponseModel>();
        public IList<DetailViewStaffTypeApiResponseModel> StaffTypes = new List<DetailViewStaffTypeApiResponseModel>();
        public IList<DetailViewStatusApiResponseModel> Statuses = new List<DetailViewStatusApiResponseModel>();
        public IList<DetailViewTypeApiResponseModel> ViewTypes = new List<DetailViewTypeApiResponseModel>();
        public IList<DetailViewTimePeriodApiResponseModel> TimePeriods = new List<DetailViewTimePeriodApiResponseModel>();
    }

    public class DetailViewLocationApiResponseModel
    {
        public int LocationId { get; set; }
        public string Code { get; set; }
        public string LocationName { get; set; }
    }

    public class DetailViewAssistTypeApiResponseModel
    {
        public int AssistTypeId { get; set; }
        public string AssistTypeName { get; set; }
    }

    public class DetailViewCategoryApiResponseModel
    {
        public int CategoryId { get; set; }
        public string Code { get; set; }
        public string CategoryName { get; set; }
    }
    public class DetailViewDayOfWeekApiResponseModel
    {
        public int DayOfWeek { get; set; }
        public string DayOfWeekName { get; set; }
    }
    public class DetailViewDefaultViewApiResponseModel
    {
        public int ViewId { get; set; }
        public string ViewName { get; set; }
    }
    public class DetailViewSearchTermApiResponseModel
    {
        public int DetailViewSearchTermId { get; set; }
        public string SearchTerm { get; set; }
    }
    public class DetailViewServiceApiResponseModel
    {
        public int ServiceId { get; set; }
        public string Code { get; set; }
        public string ServiceName { get; set; }
        public int CategoryId { get; set; }
        public string CategoryName { get; set; }
        public string CategoryCode { get; set; }
    }
    public class DetailViewStaffApiResponseModel
    {
        public int StaffId { get; set; }
        public string Code { get; set; }
        public string StaffFName { get; set; }
        public string StaffLName { get; set; }
        public string StaffFullname { get; set; }
        public int? StaffSupervisorsId { get; set; }
        public string SupervisorCode { get; set; }

    }
    public class DetailViewStaffTypeApiResponseModel
    {
        public int DetailViewStaffFilterTypeId { get; set; }
        public string StaffTypeName { get; set; }
    }
    public class DetailViewStatusApiResponseModel
    {
        public int LobbyStatusId { get; set; }
        public string StatusName { get; set; }
    }
    public class DetailViewTypeApiResponseModel
    {
        public int DetailViewTypeId { get; set; }
        public string ViewName { get; set; }
    }
    public class DetailViewTimePeriodApiResponseModel
    {
        public int DetailViewTimePeriodId { get; set; }
        public string TimePeriodName { get; set; }
    }
}
