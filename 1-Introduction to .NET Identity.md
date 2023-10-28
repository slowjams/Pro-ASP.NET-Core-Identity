1-Introduction to .NET Identity
==============================

## Custom Middleware Approach V1

```C#
//------------------V
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // ...
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseMiddleware<CustomAuthentication>();

        app.UseMiddleware<RoleMemberships>();

        app.UseRouting();

        app.UseMiddleware<CustomAuthorization>();

        app.UseEndpoints(endpoints => {
            endpoints.MapGet("/secret", SecretEndpoint.Endpoint).WithDisplayName("secret");
        });
    }
}
//------------------Ʌ

//-------------------------------V
public class CustomAuthentication
{
    private RequestDelegate next;

    public CustomAuthentication(RequestDelegate requestDelegate)
    {
        next = requestDelegate;
    }

    // an initial HttpContext contains a default asp.net auto-created ClaimsPrincipal which has auto-created ClaimsIdentity (IsAuthenticated is false) that has 0 claims
    public async Task Invoke(HttpContext context)  
    {
        string user = context.Request.Query["user"];
        if (user != null)
        {
            Claim claim = new Claim(ClaimTypes.Name, user);
            ClaimsIdentity ident = new ClaimsIdentity("QueryStringValue");
            ident.AddClaim(claim);
            context.User = new ClaimsPrincipal(ident);
        }
        await next(context);
    }
}
//-------------------------------Ʌ

//-------------------------------V
public class CustomAuthorization
{
    private RequestDelegate next;

    public CustomAuthorization(RequestDelegate requestDelegate) => next = requestDelegate;

    public async Task Invoke(HttpContext context)
    {
        if (context.GetEndpoint()?.DisplayName == "secret")
        {
            if (context.User.Identity.IsAuthenticated)
            {
                if (context.User.IsInRole("Administrator"))               
                    await next(context);
                else
                    Forbid(context);
            }
            else
                Challenge(context);
        }
        else
            await next(context);
    }

    public void Challenge(HttpContext context) => context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    public void Forbid(HttpContext context) => context.Response.StatusCode = StatusCodes.Status403Forbidden;
}
//-------------------------------Ʌ

//-------------------------------->>
public static class UsersAndClaims
{
    public static Dictionary<string, IEnumerable<string>> UserData =
        new Dictionary<string, IEnumerable<string>> {
                { "Alice", new [] { "User", "Administrator" } },
                { "Bob", new [] { "User" } },
                { "Charlie", new [] { "User"} }
    };
    public static string[] Users => UserData.Keys.ToArray();
    public static Dictionary<string, IEnumerable<Claim>> Claims =>
        UserData.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Select(role => new Claim(ClaimTypes.Role, role)), StringComparer.InvariantCultureIgnoreCase);
}
//--------------------------------<<

//--------------------------V
public class RoleMemberships
{
    private RequestDelegate next;

    public RoleMemberships(RequestDelegate requestDelegate) =>
        next = requestDelegate;

    public async Task Invoke(HttpContext context)
    {
        IIdentity mainIdent = context.User.Identity;
        if (mainIdent.IsAuthenticated && UsersAndClaims.Claims.ContainsKey(mainIdent.Name))
        {
            ClaimsIdentity ident = new ClaimsIdentity("Role");
            ident.AddClaim(new Claim(ClaimTypes.Name, mainIdent.Name));
            ident.AddClaims(UsersAndClaims.Claims[mainIdent.Name]);
            context.User.AddIdentity(ident);
        }
        await next(context);
    }
}
//--------------------------Ʌ

//-------------------------V
public class SecretEndpoint
{
    public static async Task Endpoint(HttpContext context)
    {
        await context.Response.WriteAsync("This is the secret message");
    }
}
//-------------------------Ʌ
```

## Build-in Middleware Approach

```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(opts =>   // opts is AuthenticationOptions
        {
            opts.AddScheme<AuthHandler>("qsv", "QueryStringValue");   // <--------------------
            opts.DefaultScheme = "qsv";   // <--------------------
        });
        services.AddAuthorization();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        //app.UseMiddleware<CustomAuthentication>();
        app.UseAuthentication();

        app.UseMiddleware<RoleMemberships>();

        app.UseRouting();

        app.UseMiddleware<ClaimsReporter>();

        //app.UseMiddleware<CustomAuthorization>();
        app.UseAuthorization();

        app.UseEndpoints(endpoints => {
            endpoints.MapGet("/", async context => {
                await context.Response.WriteAsync("Hello World!");
            });
            endpoints.MapGet("/secret", SecretEndpoint.Endpoint).WithDisplayName("secret");

            endpoints.Map("/signin", CustomSignInAndSignOut.SignIn);
            endpoints.Map("/signout", CustomSignInAndSignOut.SignOut);
        });
    }
}
//------------------Ʌ

//-------------------------V
public class SecretEndpoint
{
    [Authorize(Roles = "Administrator")]
    public static async Task Endpoint(HttpContext context)
    {
        await context.Response.WriteAsync("This is the secret message");
    }
}
//-------------------------Ʌ

//----------------------V
public class AuthHandler : IAuthenticationHandler
{
    private HttpContext context;
    private AuthenticationScheme scheme;

    public Task InitializeAsync(AuthenticationScheme authScheme, HttpContext httpContext)
    {
        context = httpContext;
        scheme = authScheme;
        return Task.CompletedTask;
    }

    public Task<AuthenticateResult> AuthenticateAsync()
    {
        AuthenticateResult result;
        string user = context.Request.Cookies["authUser"];
        if (user != null)
        {
            Claim claim = new Claim(ClaimTypes.Name, user);
            ClaimsIdentity ident = new ClaimsIdentity(scheme.Name);
            ident.AddClaim(claim);
            result = AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(ident), scheme.Name));
        }
        else
        {
            result = AuthenticateResult.NoResult();
        }
        return Task.FromResult(result);
    }

    public Task ChallengeAsync(AuthenticationProperties properties)  // <----------------will be called by AuthorizationMiddleware when condition meet
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
    public Task ForbidAsync(AuthenticationProperties properties)    // <----------------will be called by AuthorizationMiddleware when condition meet
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}
//----------------------Ʌ
```

=================================================================================================================================

## V2

```C#
//------------------V
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(opts =>
        {
           opts.AddScheme<AuthHandler>("qsv", "QueryStringValue");
           opts.DefaultScheme = "qsv";
        });
        // ...
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        //app.UseMiddleware<CustomAuthentication>();
        app.UseAuthentication();

        app.UseMiddleware<RoleMemberships>();

        app.UseRouting();

        //app.UseMiddleware<CustomAuthorization>();
        app.UseAuthorization();

        app.UseEndpoints(endpoints => {
            //endpoints.Map("/signin", CustomSignInAndSignOut.SignIn);
            //endpoints.Map("/signout", CustomSignInAndSignOut.SignOut);
            endpoints.MapGet("/secret", SecretEndpoint.Endpoint).WithDisplayName("secret");
            // ...
        });
    }
}
//------------------Ʌ

//-------------------------V
public class SecretEndpoint
{
    [Authorize(Roles = "Administrator")]
    public static async Task Endpoint(HttpContext context)
    {
        await context.Response.WriteAsync("This is the secret message");
    }
}
//-------------------------Ʌ
```

```C#
//----------------------V
public class AuthHandler : IAuthenticationSignInHandler
{
    private HttpContext context;
    private AuthenticationScheme scheme;

    public Task InitializeAsync(AuthenticationScheme authScheme, HttpContext httpContext)
    {
        context = httpContext;
        scheme = authScheme;
        return Task.CompletedTask;
    }

    public Task<AuthenticateResult> AuthenticateAsync()
    {
        AuthenticateResult result;
        string user = context.Request.Cookies["authUser"];
        if (user != null)
        {
            Claim claim = new Claim(ClaimTypes.Name, user);
            ClaimsIdentity ident = new ClaimsIdentity(scheme.Name);
            ident.AddClaim(claim);
            result = AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(ident), scheme.Name));
        }
        else
        {
            result = AuthenticateResult.NoResult();
        }
        return Task.FromResult(result);
    }

    public Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
    {
        context.Response.Cookies.Append("authUser", user.Identity.Name);
        return Task.CompletedTask;
    }

    public Task SignOutAsync(AuthenticationProperties properties)
    {
        context.Response.Cookies.Delete("authUser");
        return Task.CompletedTask;
    }

    public Task ChallengeAsync(AuthenticationProperties properties)
    {
        //context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Redirect("/signin/401");
        return Task.CompletedTask;
    }

    public Task ForbidAsync(AuthenticationProperties properties)
    {
        //context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.Redirect("/signin/403");
        return Task.CompletedTask;
    }
}
//----------------------Ʌ
```