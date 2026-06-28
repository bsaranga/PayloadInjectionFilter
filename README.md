# Payload Injection Filter for ASP.NET Core
A reusable payload injection filter for ASP.NET Core. This can be used to short-circuit a request if it contains any malicious contents in the JSON payload or HTTP query parameters. The detection can be specified via a regex pattern.

[![Build/Test Workflow](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-build.yml)
[![Nuget Package Publish Workflow](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-publish.yml/badge.svg)](https://github.com/bsaranga/PayloadInjectionFilter/actions/workflows/dotnet-publish.yml)

Available on [NuGet](https://www.nuget.org/packages/SpitFire.PayloadInjectionFilter/)

The package ships **two interchangeable mechanisms**:

| | MVC Action Filter | Middleware |
|---|---|---|
| Method | `AddPayloadInjectionFilter` | `AddPayloadInjectionMiddleware` / `UsePayloadInjectionMiddleware` |
| Runs | after model binding | before routing & model binding |
| Sees | the bound model object graph | the raw query string and request body |
| Covers | MVC controllers only | controllers, **minimal APIs**, Razor Pages, gRPC |
| Granularity | per-property white-listing | per-path exclusion |

Use the **filter** when you want property-level white-listing inside MVC controllers. Use the **middleware** when you want a single boundary check that covers every endpoint type (including minimal APIs) and runs before any binding cost is incurred. They can also be combined.

## Features

1. Pattern based detection of malicious strings in JSON payloads
2. Specify the HTTP methods on which the filter/middleware should execute
3. Specify the short-circuit response by setting status code, content type and body
4. Supports recursive payloads, including recursion limit specification, with built-in protection against cyclic object graphs
5. Specific properties in specific endpoints can be white-listed (filter), or whole paths excluded (middleware)
6. Optional per-entry `ExclusionPattern` that still rejects disallowed content inside otherwise white-listed properties

> **Scope — read this first.** This is a *defense-in-depth* boundary check, not a complete security control. Deny-listing characters such as `< > & ;` does **not** by itself protect against XSS or SQL injection — the real defenses remain output encoding (Razor auto-encoding, `HtmlEncoder`) and parameterized queries / an ORM. Deny-listing will also reject some legitimate input (names with `&`, rich-text fields, etc.); white-list those properties or exclude those paths. Treat this library as one cheap layer in front of those primary defenses, not a replacement for a WAF.

## Usage

The `AddPayloadInjectionFilter` method can be chained to the `AddControllers` method in a usual ASP.NET Core service configuration section. For the filter to work, you must specify the HTTP methods that it should operate on and the regex pattern that specifies a match for malicious content. The filter will check model bound objects such as custom types and plain strings bound from query parameters.

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

By default, the filter will short-circuit the request and return a response with an HTTP Status of 400, and a plain text message saying, `Request short-circuited due to malicious content.`. This can be overridden as shown below,

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

For recursive types such as this, the filter will recursively check all properties.

```csharp
var sampleRecursiveList = new RecursiveListType
{
    Data = "sample",
    NestedList = new List<RecursiveListType>
    {
        new RecursiveListType
        {
            Data = "sample",
            NestedList = new List<RecursiveListType>
            {
                new RecursiveListType
                {
                    Data = "sample"
                }
            }
        },
        new RecursiveListType
        {
            Data = "sample",
            NestedList = new List<RecursiveListType>
            {
                new RecursiveListType
                {
                    Data = "sample",
                    NestedList = new List<RecursiveListType>
                    {
                        new RecursiveListType
                        {
                            Data = "<unsafe/>"
                        }
                    }
                }
            }
        }
    }
}
```

The maximum recursion depth can be set as shown below. The default for this property is -1, meaning an infinite recursion depth.

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllers()
            .AddPayloadInjectionFilter(cfg =>
            {
                // Other overrides hidden
                cfg.MaxRecursionDepth = 10;
            });
}
```

Further more, selected properties in the models bound to selected API endpoints can be ignored by specification.

```csharp
cfg.WhiteListEntries = new List<WhiteListEntry>
{
    new WhiteListEntry
    {
        PathTemplate = "api/Services/appointmentSettings/{id}",
        ParameterName = "appointmentSetting",
        PropertyNames = new List<string>
        {
            nameof(ServiceAppointmentSetting.AdditoinalInformation)
        }
    }
};
```

A white-listed property is normally skipped entirely. If you want to allow *most* content in a property but still block a narrower set of patterns, set an `ExclusionPattern` on the entry. The property is exempt from the global `Pattern`, but the request is still short-circuited when the value matches the `ExclusionPattern`:

```csharp
cfg.WhiteListEntries = new List<WhiteListEntry>
{
    new WhiteListEntry
    {
        PathTemplate = "api/Services/appointmentSettings/{id}",
        ParameterName = "appointmentSetting",
        PropertyNames = new List<string>
        {
            nameof(ServiceAppointmentSetting.AdditoinalInformation)
        },
        // Rich text with <p>, <strong> etc. is allowed, but <script> is still rejected.
        ExclusionPattern = new Regex("<script", RegexOptions.IgnoreCase)
    }
};
```

## Using the middleware

The middleware inspects the **raw** query string and request body before model binding, so it protects every endpoint type — including minimal APIs and Razor Pages — not just MVC controllers. Register the options in service configuration and add the middleware early in the pipeline:

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPayloadInjectionMiddleware(cfg =>
{
    cfg.AllowedHttpMethods = new List<HttpMethod>
    {
        HttpMethod.Post,
        HttpMethod.Put,
        HttpMethod.Patch,
    };

    cfg.Pattern = new Regex(@"[<>\&;]");
});

var app = builder.Build();

// Place it before UseRouting / MapControllers so malicious requests are
// short-circuited before reaching any endpoint.
app.UsePayloadInjectionMiddleware();

app.MapControllers();
app.MapPost("/minimal", (SomeModel model) => Results.Ok()); // also covered

app.Run();
```

Because the middleware works on raw text it has no concept of model properties. Instead of per-property white-listing it supports **per-path exclusions** and toggles for what to scan:

```csharp
builder.Services.AddPayloadInjectionMiddleware(cfg =>
{
    cfg.Pattern = new Regex(@"[<>\&;]");

    // Custom short-circuit response (defaults: 400, text/plain, standard message).
    cfg.ResponseStatusCode = 400;
    cfg.ResponseContentType = "application/json";
    cfg.ResponseContentBody = JsonSerializer.Serialize(new { Error = "Malicious content found" });

    // Choose what is scanned (both default to true).
    cfg.ScanQueryString = true;
    cfg.ScanBody = true;

    // Bodies larger than this are rejected with 413 instead of being buffered (default 30 MB).
    cfg.MaxScannedBodyBytes = 30L * 1024 * 1024;

    // Routes that legitimately accept markup / rich text bypass scanning (prefix match).
    cfg.ExcludedPaths = new List<PathString>
    {
        "/api/content/richtext"
    };
});
```

Notes:

- The query string is URL-decoded before matching, so percent-encoded payloads such as `%3Cscript%3E` are caught.
- The request body is buffered (`EnableBuffering`) and rewound, so downstream endpoints can read it as normal.
- Only the HTTP methods in `AllowedHttpMethods` are scanned (POST, PUT, PATCH by default).

## Reliability notes

- **Cyclic object graphs** (e.g. `a.Nested = b; b.Nested = a;`) are detected via reference tracking on the traversal path, so the filter no longer stack-overflows when `MaxRecursionDepth` is left at the default `-1`.
- **Null action arguments** (optional / unbound parameters and null collection items) are skipped instead of throwing.
- Reflection metadata (`PropertyInfo`) is cached per type, so repeated requests do not re-enumerate properties on every call.
