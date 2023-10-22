1-Introduction to .NET Identity
==============================

A custom middleware approach:

```C#
//------------------V
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRazorPages();
        services.AddControllersWithViews();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseMiddleware<CustomAuthentication>();

        app.UseMiddleware<RoleMemberships>();

        app.UseRouting();

        app.UseMiddleware<CustomAuthorization>();

        app.UseEndpoints(endpoints => {
            endpoints.MapGet("/", async context => {
                await context.Response.WriteAsync("Hello World!");
            });
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
```