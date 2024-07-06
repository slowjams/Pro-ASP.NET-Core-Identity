.NET Project Based Walkthrough
==============================

## Template fun facts

```C#
//-----------------V  this is the template when a new project is created
public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();       // <------------------------
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();
                                                 // <---------------? why there is no builder.Services.AddAuthorization() required in the template
        var app = builder.Build();

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseAuthorization();   // <-------------------how does it run if the require service is not registered?

        app.MapControllers();

        app.Run();
    }
}

// builder.Services.AddControllers() does the job
private static IMvcCoreBuilder AddControllersCore(IServiceCollection services)
{
    // This method excludes all of the view-related services by default.
    var builder = services
        .AddMvcCore()
        .AddApiExplorer()
        .AddAuthorization()   // <-------------------------------
        .AddCors()
        .AddDataAnnotations()
        .AddFormatterMappings();

    // ...
    return builder;
}
//-----------------Ʌ
```

ok,  `AddControllersCore` doesn't call `AddAuthorization`, so what it fails if we do

```C#
public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();       
                                             //  no AddAuthorization registration
        var app = builder.Build();

        app.UseAuthentication();  // <--------------------------
        
        app.UseAuthorization();  

        app.MapControllers();

        app.Run();
    }
}
```
it still runs ok because there is no DI using  in the `AuthenticationMiddleware`'s constructor, check the source code you will see


We need to register `IAuthorizationHandler` but not `IAuthenticationHandler`:

```C#
public class Program
{
    public static void Main(string[] args)
    {
 
        builder.Services.AddAuthentication(opts =>
        {
            opts.AddScheme<AuthHandler>("qsv", "QueryString");    // <----------no DI required for IAuthenticationHandler
            opts.DefaultScheme = "qsv";
        });

        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("AtLeast18", policyBuider => policyBuider.Requirements.Add(new MinimumAgeRequirement(18)));
        });

        builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();  // <--------------DI required for IAuthorizationHandler
      
        // ...
    }
}
```

The reason is probably we need to name a scheme name to `IAuthenticationHandler`, so it would be difficult to do it via DI



## Fun fact or bug fact, `IAuthorizationHandler` still runs when Authentication fails?

Looking at the semi-pseudo source code:

```C#
public class AuthorizationMiddleware
{
    // ...
    public async Task Invoke(HttpContext context)
    {
        policy = await AuthorizationPolicy.CombineAsync(_policyProvider, authorizeData, policies); 

        if (policy == null)  
        {
             await _next(context);
             return;
        }

        var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();

        AuthenticateResult authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context); 

        var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult!, context, resource);  // <------------call user defined AuthorizationHandler internally
        var authorizationMiddlewareResultHandler = context.RequestServices.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
      
        await authorizationMiddlewareResultHandler
            .HandleAsync(_next, context, policy, authorizeResult);  // call IAuthenticationHandler.ChallengeAsync() or ForbidAsync() depending on                 
    }
}

public class PolicyEvaluator : IPolicyEvaluator
{
    public virtual async Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object? resource)
    { 
        var result = await _authorization.AuthorizeAsync(context.User, resource, policy); // <----------------call user defined AuthorizationHandler internally
        if (result.Succeeded)
           return PolicyAuthorizationResult.Success();
 
        // If authentication was successful, return forbidden, otherwise challenge
        return (authenticationResult.Succeeded) ?   // <--------------------------------- authenticationResult is used here to differentiate Forbid or Challenge result
            PolicyAuthorizationResult.Forbid(result.Failure) : PolicyAuthorizationResult.Challenge();  // <-------------------b4.2 that's how 401 and 403 result get determined
    }
}
```

you can see if there is a failed `AuthenticateResult`, `_authorization.AuthorizeAsync(context.User, resource, policy)` still runs, so if you have all `IAuthorizationRequirement` pass, the response is 200, not 401, and if the `IAuthorizationRequirement` fails, response is "401 Unauthorized" is it a huge bug by .NET team?



## Default Scheme and Non-default Scheme When It Comes to Challenge

When an unauthenciated user access below endpoint

```C#
public class Program
{
    public static void Main(string[] args)
    {
        //
        builder.Services.AddAuthentication(opts =>
        {
            opts.AddScheme<AuthOneHandler>("one", "first handler");
            opts.AddScheme<AuthTwoHandler>("two", "second handler");
            opts.AddScheme<AuthThreeHandler>("three", "third handler");
            opts.DefaultScheme = "one";
        });    
                                     // <-------------as explain before, not need to call builder.Services.AddAuthorization() if you have builder.Services.AddControllers()
        app.UseAuthentication();

        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}


[HttpGet]
[Authorize]   // <----------------------------------AuthOneHandler.ChallengeAsync() will be called (by AuthorizationMiddleware, not AuthenticationMiddleware, check b3 source code)
public IEnumerable<string> GetSecrets() => ...;
/*
the pipeline will be like:

    request comes in ---------> AuthenticationMiddleware (calls AuthOneHandler.AuthenticateAsync) --------->  AuthorizationMiddleware (calls AuthOneHandler.ChallengeAsync)

*/


[HttpGet]
[Authorize(AuthenticationSchemes = "two, three")] // both of AuthTwoHandler and AuthThreeHandler's ChallengeAsync() will be called, AuthOneHandler's ChallengeAsync won't be called
public IEnumerable<string> GetSecrets() => ...;

/*
the pipeline will be like:

    request comes in ---------> AuthenticationMiddleware (calls AuthOneHandler.AuthenticateAsync) --------->  AuthorizationMiddleware (calls AuthTwoHandler.AuthenticateAsync, and 
    
    AuthThreeHandler.AuthenticateAsync), check the combined authenticate result then calls AuthTwoHandler.ChallengeAsync, and ChallengeAsync.ChallengeAsync  

*/

```


## "And" and "Or"


## IAuthorizationRequirementData


## allows an IAuthorizationRequirement be its own IAuthorizationHandler, see `RolesAuthorizationRequirement` source code services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthorizationHandler, PassThroughAuthorizationHandler>());   // <-----------------------!important
so `DenyAnonymousAuthorizationRequirement` doesn't need to be registered on IAuthorizationHandler