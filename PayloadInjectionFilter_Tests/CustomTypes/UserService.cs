namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class UserService
    {
        public int UserId { get; set; }
        public string ExternalUserId { get; set; }
        public int ServiceId { get; set; }
        public string ServiceName { get; set; }
        public int Proficiency { get; set; }
        public bool OptIn { get; set; }
    }
}
