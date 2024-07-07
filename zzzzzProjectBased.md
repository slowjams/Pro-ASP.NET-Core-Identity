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

you can see if there is a failed `AuthenticateResult`, `_authorization.AuthorizeAsync(context.User, resource, policy)` still runs, so if you have all `IAuthorizationRequirement` pass, the response is 200, not 401, and if the `IAuthorizationRequirement` fails, response is "401 Unauthorized" is it a huge bug by .NET team? https://github.com/dotnet/aspnetcore/issues/56656



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
    
    AuthThreeHandler.AuthenticateAsync), check the combined authenticate result (only from "two" and "three", not one) then calls AuthTwoHandler, and AuthThree's HandlerChallengeAsync 

*/

```

when an user is authenciated by default scheme ("one") but fails on "two" and "three"

```C#
[HttpGet]
[Authorize(AuthenticationSchemes = "two, three")] // both of AuthTwoHandler and AuthThreeHandler's ChallengeAsync() will be called, AuthOneHandler's ChallengeAsync won't be called
public IEnumerable<string> GetSecrets() => ...;   // the response is still "401 - Unauthorized" even though the default scheme's authentication passes.
```

so whenever non-default scheme is used in `[AuthenticationSchemes = "xxx, yyy")]`, then default `IAuthenticationHandler.ChallengeAsync` won't be called, check n1.

And a quirk is, sometimes you see code to `AddPolicy` by new up a policy with AuthenticationSchemes

```C#
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(
        "Combined",
        new AuthorizationPolicy(new IAuthorizationRequirement[] { new MinimumAgeRequirement(18) }, authenticationSchemes: new string[] { "second", "third" })
    );
});
```

but we normally define non-default schemes in Authorize attribute as

```C#
[Authorize(Policy = "Combined", AuthenticationSchemes = "second, third")]
public IEnumerable<string> GetBeer()
{
    return Beers;
}
```

the combined policy will contains 2 distinct elements which is "second", "third",  but if you do 

```C#
[Authorize(Policy = "Combined", AuthenticationSchemes = "fourth, fifth")]
public IEnumerable<string> GetBeer()
{
    return Beers;
}
 ```

the combined policy will contains 4 elements:  "second", "third", "fourth", and "fifth".  It just a different way to specify non-default scheme I guess, the first specify non-default scheme in registration, while latter specify them in endpoints



## "And" and "Or"

What if you want to have an "Or" effect, e.g a company has doors that only open with key cards. If you leave your key card at home, the receptionist prints a temporary sticker and opens the door for you. In this scenario, you'd have a single requirement, `BuildingEntry`, but multiple handlers, each one examining a single requirement.

```C#
public class BuildingEntryRequirement : IAuthorizationRequirement { }

public class BadgeEntryHandler : AuthorizationHandler<BuildingEntryRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, BuildingEntryRequirement requirement)
    {
        if (context.User.HasClaim(
            c => c.Type == "BadgeId" && c.Issuer == "https://shoppigsecurity"))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public class TemporaryStickerHandler : AuthorizationHandler<BuildingEntryRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, BuildingEntryRequirement requirement)
    {
        if (context.User.HasClaim(
            c => c.Type == "TemporaryBadgeId" && c.Issuer == "https://shoppigsecurity"))
        {
            // Code to check expiration date omitted for brevity.
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
```
 

```C#
//--------------------------------------V
public class AuthorizationHandlerContext
{
   private readonly HashSet<IAuthorizationRequirement> _pendingRequirements;
   private List<AuthorizationFailureReason>? _failedReasons;
   private bool _failCalled;
   private bool _succeedCalled;

   public AuthorizationHandlerContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object? resource)
   {
      Requirements = requirements;
      _pendingRequirements = new HashSet<IAuthorizationRequirement>(requirements);
      // ...
   }

   public virtual IEnumerable<IAuthorizationRequirement> Requirements { get; }

   public virtual bool HasFailed { get { return _failCalled; } }

   public virtual bool HasSucceeded     // <-----------------------------
   {
      get {
         return !_failCalled && _succeedCalled && !PendingRequirements.Any();  // <-----------------------------
      }
   }

   public virtual void Fail() // <---why we need to call Fail() when we can just simply not call Succeed(requirement), the docs says it gurantee fail, probably other handler can reset etc
   {                              
      _failCalled = true;
   }

   public virtual void Fail(AuthorizationFailureReason reason)
   {
      Fail();
      if (reason != null)
      {
         // ...
         _failedReasons.Add(reason);
      }
   }

   public virtual void Succeed(IAuthorizationRequirement requirement)  
   {
      _succeedCalled = true;
      _pendingRequirements.Remove(requirement);  // <--------------we only have one single instance of `BuildingEntryRequirement`, once it is removed  by one of handlers, it is "Or" effect
   } 
}
//--------------------------------------Ʌ
```


##  A Requirement is both `IAuthorizationRequirement` and `IAuthorizationHandler`

Ut's possible to bundle both a requirement and a handler into a single class implementing both IAuthorizationRequirement and IAuthorizationHandler. This bundling creates a tight coupling between the handler and requirement and is **only recommended for simple requirements and handlers**. Creating a class that implements both interfaces **removes the need to register the handler in DI** because of the built-in PassThroughAuthorizationHandler that allows requirements to handle themselves


```C#
services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthorizationHandler, PassThroughAuthorizationHandler>()); 

public class PassThroughAuthorizationHandler : IAuthorizationHandler
{
   private readonly AuthorizationOptions _options;

   public PassThroughAuthorizationHandler() : this(Options.Create(new AuthorizationOptions())) { }

   public PassThroughAuthorizationHandler(IOptions<AuthorizationOptions> options) => _options = options.Value;

   public async Task HandleAsync(AuthorizationHandlerContext context)
   {
      foreach (var handler in context.Requirements.OfType<IAuthorizationHandler>())
      {
         await handler.HandleAsync(context).ConfigureAwait(false);
         if (!_options.InvokeHandlersAfterFailure && context.HasFailed)
         {
            break;
         }
      }
   }
}

public class AssertionRequirement : IAuthorizationHandler, IAuthorizationRequirement
{
    public Func<AuthorizationHandlerContext, Task<bool>> Handler { get; }

    public AssertionRequirement(Func<AuthorizationHandlerContext, bool> handler)
    { 
        Handler = context => Task.FromResult(handler(context));
    }

    public AssertionRequirement(Func<AuthorizationHandlerContext, Task<bool>> handler)
    { 
        Handler = handler;
    }

    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        if (await Handler(context).ConfigureAwait(false))
        {
            context.Succeed(this);
        }
    }
}
```

you can also use `IAuthorizationRequirementData` so that you don't need to specify a policy name. e.g traditional approach is

```C#
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AtLeast18", policyBuider => policyBuider.AddRequirements(new MinimumAgeRequirement(18)));
});

[HttpGet]
[Authorize(Policy = "AtLeast18")]
public IEnumerable<string> GetSecrets() => ...;
```

with `IAuthorizationRequirementData` in .NET 8:

```C#
public class MinimumAgeAuthorizeAttribute : AuthorizeAttribute, IAuthorizationRequirement, IAuthorizationRequirementData
{
    public MinimumAgeAuthorizeAttribute(int age) => Age = age;
    public int Age { get; }

    public IEnumerable<IAuthorizationRequirement> GetRequirements()
    {
        yield return this;
    }
}

// no need to call options.AddPolicy("AtLeast18", policyBuider => policyBuider.AddRequirements(new MinimumAgeRequirement(18)));

[HttpGet]
[MinimumAgeAuthorize(18)]
public IEnumerable<string> GetSecrets() => ...;
```



