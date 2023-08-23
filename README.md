# Payload Injection Filter for ASP.NET Core
A reusable payload injection filter for ASP.NET Core. This can be used to short-circuit a request if it contains any malicious content as specified via a regex pattern.

[![Build/Test Workflow](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-build.yml)
[![Nuget Package Publish Workflow](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-publish.yml/badge.svg)](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-publish.yml)

Available on [NuGet](https://www.nuget.org/packages/Zone24x7.PayloadInjectionFilter/)

## Usage

The `AddPayloadInjectionFilter` method can be chained to the `AddControllers` method in a usual ASP.NET Core service configuration section. For the filter to work, you must specify the HTTP methods that it should operate on and the regex pattern that specifies a match for malicious content. The filter will check model bound bodies such as custom types and plain strings bound from query parameters.

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

By default, the filter will short-circuit the request and return a response with HTTP Status 400, and a plain text message saying, `Request short-circuited due to malicious content.`. This can be overridden as shown below,

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
                cfg.ResponseStatusCode = 400;
                cfg.ResponseContentType = "application/json";
                cfg.ResponseContentBody = JsonSerializer.Serialize(new
                {
                    Error = "Malicious content found"
                });
            });
}
```
