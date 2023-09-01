namespace PayloadInjectionFilter_Tests.CustomTypes
{
    internal class RecursiveListType
    {
        public string Data { get; set; }
        public List<RecursiveListType> NestedList { get; set; }
    }
}
