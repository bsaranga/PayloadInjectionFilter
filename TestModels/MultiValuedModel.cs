namespace TestModels
{
    public class MultiValuedModel
    {
        public MultiValuedModel(string Value1, string Value2, string Value3)
        {
            this.Value1 = Value1;
            this.Value2 = Value2;
            this.Value3 = Value3;
        }

        public string Value1 { get; }
        public string Value2 { get; }
        public string Value3 { get; }
    }
}
