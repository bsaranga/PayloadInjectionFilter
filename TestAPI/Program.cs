using System.Text.RegularExpressions;
using Zone24x7PayloadExtensionFilter;

namespace TestAPI
{
    // Change
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllers()
                            .AddPayloadInjectionFilter(cfg =>
                            {
                                cfg.AllowedHttpMethods = new List<HttpMethod>
                                {
                                    HttpMethod.Post,
                                    HttpMethod.Put,
                                    HttpMethod.Patch,
                                };

                                cfg.Pattern = new Regex(@"[<>\&;]");
                            });

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}