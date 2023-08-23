# Payload Injection Filter for ASP.NET Core
A reusable payload injection filter for ASP.NET Core. This can be used to short-circuit a request if it contains any malicious content as specified via a regex pattern.

[![Build/Test Workflow](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-build.yml)
[![Nuget Package Publish Workflow](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-publish.yml/badge.svg)](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-publish.yml)

## Usage

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllers()
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
}
```
