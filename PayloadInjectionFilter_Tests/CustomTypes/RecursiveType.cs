namespace PayloadInjectionFilter_Tests.CustomTypes
{
    public class RecursiveType
    {
        public string Text1 { get; set; }
        public string Text2 { get; set; }
        public RecursiveType Nested { get; set; }
    }
}
