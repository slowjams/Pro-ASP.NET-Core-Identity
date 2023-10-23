.NET Identity Source Code
==============================

```C#
//------------------>>
public class Startup 
{
   public void ConfigureServices(IServiceCollection services) { }

   public void Configure(IApplicationBuilder app, IWebHostEnvironment env) 
   {

   }
}
//------------------<<
```

**Authentication**

```C#
//-----------------------------------------------------------V
public static class AuthenticationServiceCollectionExtensions
{
   public static AuthenticationBuilder AddAuthentication(this IServiceCollection services)
   { 
      services.AddAuthenticationCore();
      services.AddDataProtection();
      services.AddWebEncoders();
      services.TryAddSingleton(TimeProvider.System);
      #pragma warning disable CS0618 // Type or member is obsolete
      services.TryAddSingleton<ISystemClock, SystemClock>();
      #pragma warning restore CS0618 // Type or member is obsolete
      services.TryAddSingleton<IAuthenticationConfigurationProvider, DefaultAuthenticationConfigurationProvider>();
 
      return new AuthenticationBuilder(services);
   }

   public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, string defaultScheme)
      => services.AddAuthentication(o => o.DefaultScheme = defaultScheme);
   
   public static AuthenticationBuilder AddAuthentication(this IServiceCollection services, Action<AuthenticationOptions> configureOptions)
   { 
      var builder = services.AddAuthentication();
      services.Configure(configureOptions);
      return builder;
   }
}
//-----------------------------------------------------------Ʌ

//---------------------------------------------------------------V
public static class AuthenticationCoreServiceCollectionExtensions
{
   public static IServiceCollection AddAuthenticationCore(this IServiceCollection services)
   { 
      services.TryAddScoped<IAuthenticationService, AuthenticationService>();
      services.TryAddSingleton<IClaimsTransformation, NoopClaimsTransformation>(); // Can be replaced with scoped ones that use DbContext
      services.TryAddScoped<IAuthenticationHandlerProvider, AuthenticationHandlerProvider>();
      services.TryAddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();
      return services;
   }

   public static IServiceCollection AddAuthenticationCore(this IServiceCollection services, Action<AuthenticationOptions> configureOptions)
   {
      services.AddAuthenticationCore();
      services.Configure(configureOptions);
      return services;
   }
}
//---------------------------------------------------------------Ʌ
```

**Authorization**

```C#
//---------------------------------------------------V
public static class PolicyServiceCollectionExtensions
{
   public static AuthorizationBuilder AddAuthorizationBuilder(this IServiceCollection services)
      => new AuthorizationBuilder(services.AddAuthorization());

   public static IServiceCollection AddAuthorizationPolicyEvaluator(this IServiceCollection services)
   {
      services.TryAddSingleton<AuthorizationPolicyMarkerService>();
      services.TryAddTransient<IPolicyEvaluator, PolicyEvaluator>();
      services.TryAddTransient<IAuthorizationMiddlewareResultHandler, AuthorizationMiddlewareResultHandler>();
      return services;
   }

   public static IServiceCollection AddAuthorization(this IServiceCollection services)
   { 
      services.AddAuthorizationCore();
      services.AddAuthorizationPolicyEvaluator();
      services.TryAddSingleton<AuthorizationPolicyCache>();
      return services;
   }

   public static IServiceCollection AddAuthorization(this IServiceCollection services, Action<AuthorizationOptions> configure)
   { 
      services.AddAuthorizationCore(configure);
      services.AddAuthorizationPolicyEvaluator();
      services.TryAddSingleton<AuthorizationPolicyCache>();
      return services;
   }
}
//---------------------------------------------------Ʌ

//----------------------------------------------------------V
public static class AuthorizationServiceCollectionExtensions
{
   public static IServiceCollection AddAuthorizationCore(this IServiceCollection services)
   {
      // These services depend on options, and they are used in Blazor WASM, where options aren't included by default.
      services.AddOptions();
 
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationService, DefaultAuthorizationService>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationPolicyProvider, DefaultAuthorizationPolicyProvider>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerProvider, DefaultAuthorizationHandlerProvider>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationEvaluator, DefaultAuthorizationEvaluator>());
      services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerContextFactory, DefaultAuthorizationHandlerContextFactory>());
      services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthorizationHandler, PassThroughAuthorizationHandler>());
      
      return services;
   }

   public static IServiceCollection AddAuthorizationCore(this IServiceCollection services, Action<AuthorizationOptions> configure)
   { 
      services.Configure(configure);
      return services.AddAuthorizationCore();
   }
}
//----------------------------------------------------------Ʌ

//---------------------------------------------------V
public static class AuthorizationAppBuilderExtensions
{
   internal const string AuthorizationMiddlewareSetKey = "__AuthorizationMiddlewareSet";

   public static IApplicationBuilder UseAuthorization(this IApplicationBuilder app)
   { 
      VerifyServicesRegistered(app);
 
      app.Properties[AuthorizationMiddlewareSetKey] = true;
      return app.UseMiddleware<AuthorizationMiddleware>();
   }

   private static void VerifyServicesRegistered(IApplicationBuilder app)
    {
        // Verify that AddAuthorizationPolicy was called before calling UseAuthorization. We use the AuthorizationPolicyMarkerService to ensure all the services were added.
        if (app.ApplicationServices.GetService(typeof(AuthorizationPolicyMarkerService)) == null)
        {
            throw new InvalidOperationException(Resources.FormatException_UnableToFindServices(nameof(IServiceCollection), nameof(PolicyServiceCollectionExtensions.AddAuthorization)));
        }
    }
}
//---------------------------------------------------Ʌ

//----------------------------------V
public class AuthorizationMiddleware
{
   private const string SuppressUseHttpContextAsAuthorizationResource = "Microsoft.AspNetCore.Authorization.SuppressUseHttpContextAsAuthorizationResource";
 
   // Property key is used by Endpoint routing to determine if Authorization has run
   private const string AuthorizationMiddlewareInvokedWithEndpointKey = "__AuthorizationMiddlewareWithEndpointInvoked";
   private static readonly object AuthorizationMiddlewareWithEndpointInvokedValue = new object();
 
   private readonly RequestDelegate _next;
   private readonly IAuthorizationPolicyProvider _policyProvider;
   private readonly bool _canCache;
   private readonly AuthorizationPolicyCache? _policyCache;
   private readonly ILogger<AuthorizationMiddleware>? _logger;

   public AuthorizationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider)
   {
      _next = next ?? throw new ArgumentNullException(nameof(next));
      _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
      _canCache = false;
   }

   public AuthorizationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider, IServiceProvider services, ILogger<AuthorizationMiddleware> logger) 
      : this(next, policyProvider, services)
   {
      _logger = logger;
   }

   public AuthorizationMiddleware(RequestDelegate next, IServiceProvider services) : this(next, policyProvider)
   { 
      if (_policyProvider.AllowsCachingPolicies)
      {
         _policyCache = services.GetService<AuthorizationPolicyCache>();
         _canCache = _policyCache != null;
      }
   }

   public async Task Invoke(HttpContext context)
   {
      var endpoint = context.GetEndpoint();
      if (endpoint != null)
      {
         // EndpointRoutingMiddleware uses this flag to check if the Authorization middleware processed auth metadata on the endpoint.
         // The Authorization middleware can only make this claim if it observes an actual endpoint.
         context.Items[AuthorizationMiddlewareInvokedWithEndpointKey] = AuthorizationMiddlewareWithEndpointInvokedValue;
      }

      // Use the computed policy for this endpoint if we can
      AuthorizationPolicy? policy = null;
      var canCachePolicy = _canCache && endpoint != null;
      if (canCachePolicy)
      {
         policy = _policyCache!.Lookup(endpoint!);
      }

      if (policy == null)
      {
         // IMPORTANT: Changes to authorization logic should be mirrored in MVC's AuthorizeFilter
         var authorizeData = endpoint?.Metadata.GetOrderedMetadata<IAuthorizeData>() ?? Array.Empty<IAuthorizeData>();
 
         var policies = endpoint?.Metadata.GetOrderedMetadata<AuthorizationPolicy>() ?? Array.Empty<AuthorizationPolicy>();
 
         policy = await AuthorizationPolicy.CombineAsync(_policyProvider, authorizeData, policies);
 
         var requirementData = endpoint?.Metadata?.GetOrderedMetadata<IAuthorizationRequirementData>() ?? Array.Empty<IAuthorizationRequirementData>();
         if (requirementData.Count > 0)
         {
            var reqPolicy = new AuthorizationPolicyBuilder();
            foreach (var rd in requirementData)
            {
               foreach (var r in rd.GetRequirements())
               {
                  reqPolicy.AddRequirements(r);
               }
            }
 
            // Combine policy with requirements or just use requirements if no policy
            policy = policy is null ? reqPolicy.Build() : AuthorizationPolicy.Combine(policy, reqPolicy.Build());
         }
 
         // Cache the computed policy
         if (policy != null && canCachePolicy)
         {
            _policyCache!.Store(endpoint!, policy);
         }      
      }

      if (policy == null)
      {
         await _next(context);
         return;
      }

      var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();

      var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);
      if (authenticateResult?.Succeeded ?? false)
      {
         if (context.Features.Get<IAuthenticateResultFeature>() is IAuthenticateResultFeature authenticateResultFeature)
         {
            authenticateResultFeature.AuthenticateResult = authenticateResult;
         }
         else
         {
            var authFeatures = new AuthenticationFeatures(authenticateResult);
            context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
            context.Features.Set<IAuthenticateResultFeature>(authFeatures);
         }
      }

      // Allow Anonymous still wants to run authorization to populate the User but skips any failure/challenge handling
      if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
      {
         await _next(context);
         return;
      }
 
      if (authenticateResult != null && !authenticateResult.Succeeded && _logger is ILogger log && log.IsEnabled(LogLevel.Debug))
      {
         log.LogDebug("Policy authentication schemes {policyName} did not succeed", String.Join(", ", policy.AuthenticationSchemes));
      }

      object? resource;
      if (AppContext.TryGetSwitch(SuppressUseHttpContextAsAuthorizationResource, out var useEndpointAsResource) && useEndpointAsResource)
      {
         resource = endpoint;
      }
      else
      {
         resource = context;
      }
 
      var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult!, context, resource);
      var authorizationMiddlewareResultHandler = context.RequestServices.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
      
      await authorizationMiddlewareResultHandler.HandleAsync(_next, context, policy, authorizeResult);
   }
}
//----------------------------------Ʌ
```

```C#
//------------------------------------------>>
public static class AuthAppBuilderExtensions
{
   internal const string AuthenticationMiddlewareSetKey = "__AuthenticationMiddlewareSet";

   public static IApplicationBuilder UseAuthentication(this IApplicationBuilder app)
   {
      app.Properties[AuthenticationMiddlewareSetKey] = true;
      return app.UseMiddleware<AuthenticationMiddleware>();
   }
}
//------------------------------------------<<

//-----------------------------------V
public class AuthenticationMiddleware
{
   private readonly RequestDelegate _next;

   public AuthenticationMiddleware(RequestDelegate next, IAuthenticationSchemeProvider schemes)
   {
      _next = next;
      Schemes = schemes;
   }

   public IAuthenticationSchemeProvider Schemes { get; set; }

   public async Task Invoke(HttpContext context)
   {
      context.Features.Set<IAuthenticationFeature>(new AuthenticationFeature
      {
         OriginalPath = context.Request.Path,
         OriginalPathBase = context.Request.PathBase
      });

      // Give any IAuthenticationRequestHandler schemes a chance to handle the request
      var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
      foreach (var scheme in await Schemes.GetRequestHandlerSchemesAsync())
      {
         var handler = await handlers.GetHandlerAsync(context, scheme.Name) as IAuthenticationRequestHandler;
         
         if (handler != null && await handler.HandleRequestAsync())
            return;
      }
 
      var defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();
      if (defaultAuthenticate != null)
      {
         var result = await context.AuthenticateAsync(defaultAuthenticate.Name);
         if (result?.Principal != null)
         {
            context.User = result.Principal;
         }
         if (result?.Succeeded ?? false)
         {
            var authFeatures = new AuthenticationFeatures(result);
            context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
            context.Features.Set<IAuthenticateResultFeature>(authFeatures);
         }
      }

      await _next(context);
   }
}
//-----------------------------------Ʌ
```

========================================================================================================

```C#
/*
public static class ClaimTypes
{
   public const string Actor = "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor";
   public const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
   public const string Rsa = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/rsa";
   public const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
   public const string Email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
   public const string Gender = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender";
   public const string GivenName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
   // ...
}
*/

//----------------V
public class Claim
{
   private enum SerializationMask
   {
      None = 0,
      NameClaimType = 1,
      RoleClaimType = 2,
      StringType = 4,
      Issuer = 8,
      OriginalIssuerEqualsIssuer = 16,
      OriginalIssuer = 32,
      HasProperties = 64,
      UserData = 128,
   }
   
   private readonly byte[] _userSerializationData;
 
   private readonly string _issuer;
   private readonly string _originalIssuer;
   private Dictionary<string, string> _properties;
 
   private readonly ClaimsIdentity _subject;  // <---------------------
   private readonly string _type;
   private readonly string _value;
   private readonly string _valueType;

   public Claim(BinaryReader reader) : this(reader, null) { }

   public Claim(BinaryReader reader, ClaimsIdentity subject)
   {
      _subject = subject;

      SerializationMask mask = (SerializationMask)reader.ReadInt32();
      int numPropertiesRead = 1;
      int numPropertiesToRead = reader.ReadInt32();
      _value = reader.ReadString();

      if ((mask & SerializationMask.NameClaimType) == SerializationMask.NameClaimType) {
         _type = ClaimsIdentity.DefaultNameClaimType;
      }
      else if ((mask & SerializationMask.RoleClaimType) == SerializationMask.RoleClaimType) {
         _type = ClaimsIdentity.DefaultRoleClaimType;
      }
      else {
         _type = reader.ReadString();
      }

      // ...
   }

   protected Claim(Claim other) : this(other, (other == null ? (ClaimsIdentity)null : other._subject)) { }

   protected Claim(Claim other, ClaimsIdentity? subject) {
       // ...
   }

   public Claim(string type, string value) : this(type, value, ClaimValueTypes.String, ClaimsIdentity.DefaultIssuer, ClaimsIdentity.DefaultIssuer, (ClaimsIdentity?)null) { }

   internal Claim(string type, string value, string valueType, string issuer, string originalIssuer, ClaimsIdentity subject, string propertyKey, string propertyValue)
   {
      _type = type;
      _value = value;
      _valueType = string.IsNullOrEmpty(valueType) ? ClaimValueTypes.String : valueType;
      _issuer = string.IsNullOrEmpty(issuer) ? ClaimsIdentity.DefaultIssuer : issuer;
      _originalIssuer = string.IsNullOrEmpty(originalIssuer) ? _issuer : originalIssuer;
      _subject = subject;
 
      if (propertyKey != null)
      {
         _properties = new Dictionary<string, string>();
         _properties[propertyKey] = propertyValue!;
      }
   }

   protected virtual byte[] CustomSerializationData => _userSerializationData;

   //
   public string Issuer => _issuer;

   public string OriginalIssuer => _originalIssuer;

   public IDictionary<string, string> Properties => _properties ??= new Dictionary<string, string>();

   public ClaimsIdentity Subject => _subject;   // <------

   public string Type => _type;

   public string Value => _value;

   public string ValueType => _valueType;
   //

   public virtual Claim Clone()
   {
      return Clone((ClaimsIdentity)null);
   }

   public virtual Claim Clone(ClaimsIdentity identity)
   {
      return new Claim(this, identity);
   }

   public virtual void WriteTo(BinaryWriter writer)
   {
      WriteTo(writer, null);
   }

   protected virtual void WriteTo(BinaryWriter writer, byte[] userData)
   {
      // ...
   }
   public override string ToString()
   {
      return _type + ": " + _value;
   }
}
//----------------Ʌ

//------------------------>>
public interface IIdentity
{
   string AuthenticationType { get; }
   bool IsAuthenticated { get; }
   string Name { get; }
}
//------------------------<<

//-------------------------V
public class ClaimsIdentity : IIdentity
{
   private enum SerializationMask
   {
      None = 0,
      AuthenticationType = 1,
      BootstrapConext = 2,
      NameClaimType = 4,
      RoleClaimType = 8,
      HasClaims = 16,
      HasLabel = 32,
      Actor = 64,
      UserData = 128,
   }

   private byte[]? _userSerializationData;
   private ClaimsIdentity? _actor;   // <--------------------
   private string? _authenticationType;
   private object? _bootstrapContext;
   private List<List<Claim>>? _externalClaims;
   private string? _label;
   private readonly List<Claim> _instanceClaims = new List<Claim>();   // <--------------------
   private string _nameClaimType = DefaultNameClaimType;   // <-------
   private string _roleClaimType = DefaultRoleClaimType;
 
   public const string DefaultIssuer = @"LOCAL AUTHORITY";
   public const string DefaultNameClaimType = ClaimTypes.Name;
   public const string DefaultRoleClaimType = ClaimTypes.Role;

   public ClaimsIdentity() : this((IIdentity?)null, (IEnumerable<Claim>?)null, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(IIdentity identity) : this(identity, (IEnumerable<Claim>?)null, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(string? authenticationType) : this((IIdentity?)null, (IEnumerable<Claim>?)null, authenticationType, (string?)null, (string?)null) { }

   public ClaimsIdentity(IEnumerable<Claim>? claims, string? authenticationType) : this((IIdentity?)null, claims, authenticationType, (string?)null, (string?)null) { }

   public ClaimsIdentity(IIdentity? identity, IEnumerable<Claim>? claims) : this(identity, claims, (string?)null, (string?)null, (string?)null) { }

   public ClaimsIdentity(string? authenticationType, string? nameType, string? roleType) : this(...) { }

   public ClaimsIdentity(IEnumerable<Claim>? claims, string? authenticationType, string? nameType, string? roleType) : this(...) { }

   public ClaimsIdentity(IIdentity? identity, IEnumerable<Claim>? claims, string? authenticationType, string? nameType, string? roleType)
   {
      ClaimsIdentity? claimsIdentity = identity as ClaimsIdentity;

      _authenticationType = (identity != null && string.IsNullOrEmpty(authenticationType)) ? identity.AuthenticationType : authenticationType;
      _nameClaimType = !string.IsNullOrEmpty(nameType) ? nameType : (claimsIdentity != null ? claimsIdentity._nameClaimType : DefaultNameClaimType);
      _roleClaimType = !string.IsNullOrEmpty(roleType) ? roleType : (claimsIdentity != null ? claimsIdentity._roleClaimType : DefaultRoleClaimType);

      if (claimsIdentity != null)
      {
         _label = claimsIdentity._label;
         _bootstrapContext = claimsIdentity._bootstrapContext;

         if (claimsIdentity.Actor != null)
         {
            if (!IsCircular(claimsIdentity.Actor))
            {
               _actor = claimsIdentity.Actor;
            }
            else
            {
               throw new InvalidOperationException(SR.InvalidOperationException_ActorGraphCircular);
            }
         }
         SafeAddClaims(claimsIdentity._instanceClaims);
      }
      else {
         if (identity != null && !string.IsNullOrEmpty(identity.Name))
         {
            SafeAddClaim(new Claim(_nameClaimType, identity.Name, ClaimValueTypes.String, DefaultIssuer, DefaultIssuer, this));
         }
      }

      if (claims != null)
      {
         SafeAddClaims(claims);
      }
   }

   public ClaimsIdentity(BinaryReader reader) 
   {
      Initialize(reader);
   }

   protected ClaimsIdentity(ClaimsIdentity other)
   {
      if (other._actor != null)
      {
         _actor = other._actor.Clone();
      }
 
      _authenticationType = other._authenticationType;
      _bootstrapContext = other._bootstrapContext;
      _label = other._label;
      _nameClaimType = other._nameClaimType;
      _roleClaimType = other._roleClaimType;
      if (other._userSerializationData != null)
      {
         _userSerializationData = other._userSerializationData.Clone() as byte[];
      }
 
      SafeAddClaims(other._instanceClaims);
   }

   protected virtual byte[]? CustomSerializationData => _userSerializationData;

   internal List<List<Claim>> ExternalClaims => _externalClaims ??= new List<List<Claim>>();

   public string? Label { get { return _label; } set { _label = value; } }

   public string NameClaimType => _nameClaimType;   // <------------ClaimTypes.Name;

   public string RoleClaimType => _roleClaimType;   // <------------ClaimTypes.Role;
  
   public virtual string? AuthenticationType => _authenticationType;  // <-------------

   public virtual bool IsAuthenticated => !string.IsNullOrEmpty(_authenticationType);  // <----------        

   public virtual string? Name {   // <-------------
      get {
         Claim? claim = FindFirst(_nameClaimType);
         if (claim != null)
            return claim.Value;
 
         return null;
      }      
   }

   public virtual Claim? FindFirst(string type)
   {
      foreach (Claim claim in Claims)
      {
         if (claim != null)
         {
            if (string.Equals(claim.Type, type, StringComparison.OrdinalIgnoreCase))
            {
               return claim;
            }
         }
      }
 
      return null;
   }

   public ClaimsIdentity? Actor
   {
      get { return _actor; }
      set {
         if (value != null) 
         {
            if (IsCircular(value))
               throw new InvalidOperationException(SR.InvalidOperationException_ActorGraphCircular);                  
         }
         _actor = value;
      }
   } 

   public object? BootstrapContext
   {
      get { return _bootstrapContext; }
      set { _bootstrapContext = value; }
   }

   public virtual IEnumerable<Claim> Claims
   {
      get {
         if (_externalClaims == null)
             return _instanceClaims;
 
         return CombinedClaimsIterator();
      }
   }

   private IEnumerable<Claim> CombinedClaimsIterator()
   {
      for (int i = 0; i < _instanceClaims.Count; i++)
         yield return _instanceClaims[i];
 
      for (int j = 0; j < _externalClaims!.Count; j++)
      {
         if (_externalClaims[j] != null)
         {
            foreach (Claim claim in _externalClaims[j])
               yield return claim;
         }
      }
   }

   public virtual void AddClaim(Claim claim)
   {
      if (object.ReferenceEquals(claim.Subject, this))
         _instanceClaims.Add(claim);
      else
         _instanceClaims.Add(claim.Clone(this));
   }

   public virtual void AddClaims(IEnumerable<Claim?> claims);

   // no ArgumentNullException.ThrowIfNull(claims);
   private void SafeAddClaim(Claim? claim);
   private void SafeAddClaims(IEnumerable<Claim?> claims);
   //

   public virtual bool TryRemoveClaim(Claim? claim)
   {
      if (claim == null)
         return false;
 
      bool removed = false;
 
      for (int i = 0; i < _instanceClaims.Count; i++)
      {
         if (object.ReferenceEquals(_instanceClaims[i], claim))
         {
            _instanceClaims.RemoveAt(i);
            removed = true;
            break;
         }
      }
      return removed;
   }

   public virtual void RemoveClaim(Claim? claim)
   {
      if (!TryRemoveClaim(claim))
         throw new InvalidOperationException(SR.Format(SR.InvalidOperation_ClaimCannotBeRemoved, claim));
            
   }

   public virtual IEnumerable<Claim> FindAll(Predicate<Claim> match)
   {
      return Core(match);
 
      IEnumerable<Claim> Core(Predicate<Claim> match)
      {
         foreach (Claim claim in Claims)
         {
            if (match(claim))
               yield return claim;
         }
      }
   }

   public virtual IEnumerable<Claim> FindAll(string type);

   public virtual Claim? FindFirst(Predicate<Claim> match);

   public virtual Claim? FindFirst(string type);

   public virtual bool HasClaim(Predicate<Claim> match);

   public virtual bool HasClaim(string type, string value);

   private bool IsCircular(ClaimsIdentity subject)
   {
      if (ReferenceEquals(this, subject))
         return true;
 
      ClaimsIdentity currSubject = subject;
 
      while (currSubject.Actor != null)
      {
         if (ReferenceEquals(this, currSubject.Actor))
            return true;
 
         currSubject = currSubject.Actor;
      }
 
      return false;
   }

   // ...  BinaryWriter related methods leaved out

   public virtual ClaimsIdentity Clone()
   {
      return new ClaimsIdentity(this);
   }
}
//-------------------------Ʌ

//------------------------->>
public interface IPrincipal
{
   IIdentity Identity { get; }
   bool IsInRole(string role);
}
//-------------------------<<

//--------------------------V
public class ClaimsPrincipal : IPrincipal
{
   private enum SerializationMask
   {
      None = 0,
      HasIdentities = 1,
      UserData = 2
   }

   private readonly List<ClaimsIdentity> _identities = new List<ClaimsIdentity>();
   private readonly byte[]? _userSerializationData;
 
   private static Func<IEnumerable<ClaimsIdentity>, ClaimsIdentity?> s_identitySelector = SelectPrimaryIdentity;
   private static Func<ClaimsPrincipal> s_principalSelector = ClaimsPrincipalSelector;
 
   public ClaimsPrincipal() { }

   public ClaimsPrincipal(IEnumerable<ClaimsIdentity> identities)
   {
      _identities.AddRange(identities);
   }

   public ClaimsPrincipal(IIdentity identity)
   { 
      if (identity is ClaimsIdentity ci)
         identities.Add(ci);
      else
         _identities.Add(new ClaimsIdentity(identity));
   }

   public ClaimsPrincipal(IPrincipal principal)
   {
      ClaimsPrincipal? cp = principal as ClaimsPrincipal;
      if (null == cp)
         _identities.Add(new ClaimsIdentity(principal.Identity));
      else
         if (null != cp.Identities)
            _identities.AddRange(cp.Identities);          
   }

   private static ClaimsPrincipal? SelectClaimsPrincipal()
   {
      IPrincipal? threadPrincipal = Thread.CurrentPrincipal;
 
      return threadPrincipal switch {
         ClaimsPrincipal claimsPrincipal => claimsPrincipal, not null => new ClaimsPrincipal(threadPrincipal), null => null
      };
   }

   private static ClaimsIdentity? SelectPrimaryIdentity(IEnumerable<ClaimsIdentity> identities)   // <-------------
   { 
      foreach (ClaimsIdentity identity in identities)
      {
         if (identity != null)        
            return identity;              
      }
 
      return null;
   }

   public static Func<IEnumerable<ClaimsIdentity>, ClaimsIdentity?> PrimaryIdentitySelector
   {
      get {
         return s_identitySelector;
      }
      set {
         s_identitySelector = value;
      }
   }

   public static Func<ClaimsPrincipal> ClaimsPrincipalSelector
   {
      get {
         return s_principalSelector;
      }
      set {
         s_principalSelector = value;
      }
   }

   public virtual void AddIdentity(ClaimsIdentity identity)
   { 
      _identities.Add(identity);
   }

   public virtual void AddIdentities(IEnumerable<ClaimsIdentity> identities)
   { 
      _identities.AddRange(identities);
   }

   public virtual IEnumerable<Claim> Claims
   {
      get {
         foreach (ClaimsIdentity identity in Identities) {
            foreach (Claim claim in identity.Claims) {
               yield return claim;
            }
         }
      }
   }

   protected virtual byte[]? CustomSerializationData => _userSerializationData;
  
   public virtual ClaimsPrincipal Clone() => new ClaimsPrincipal(this);

   public static ClaimsPrincipal? Current
   {
      get {
         return s_principalSelector is not null ? s_principalSelector() : SelectClaimsPrincipal();
      }
   }

   public virtual IEnumerable<Claim> FindAll(Predicate<Claim> match)
   {
      return Core(match);
 
      IEnumerable<Claim> Core(Predicate<Claim> match)
      {
         foreach (ClaimsIdentity identity in Identities)
         {
            if (identity != null)
            {
               foreach (Claim claim in identity.FindAll(match))                 
                  yield return claim;                       
            }
         }
      }
   }

   public virtual IEnumerable<Claim> FindAll(string type);

   public virtual Claim? FindFirst(Predicate<Claim> match);

   public virtual Claim? FindFirst(string type);

   public virtual bool HasClaim(Predicate<Claim> match)
   { 
      for (int i = 0; i < _identities.Count; i++)
      {
         if (_identities[i] != null)
         {
            if (_identities[i].HasClaim(match))                   
               return true;                  
         }
      }
 
      return false;
   }

   public virtual bool HasClaim(string type, string value);

   public virtual IEnumerable<ClaimsIdentity> Identities => _identities;  // <-----------------

   public virtual System.Security.Principal.IIdentity? Identity {  // <-----------------
      get {
         if (s_identitySelector != null)                
            return s_identitySelector(_identities);               
         else               
            return SelectPrimaryIdentity(_identities);               
      }
   }

   public virtual bool IsInRole(string role)
   {
      for (int i = 0; i < _identities.Count; i++)
      {
         if (_identities[i] != null)
         {
            if (_identities[i].HasClaim(_identities[i].RoleClaimType, role))             
               return true;                  
         }
      }
 
      return false;
   }
}
//--------------------------Ʌ
```

```C#
//--------------------------V
public class PolicyEvaluator : IPolicyEvaluator
{
   private readonly IAuthorizationService _authorization;

   public PolicyEvaluator(IAuthorizationService authorization)
   {
      _authorization = authorization;
   }

   public virtual async Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context)
   {
      if (policy.AuthenticationSchemes != null && policy.AuthenticationSchemes.Count > 0)
      {
         ClaimsPrincipal? newPrincipal = null;
         DateTimeOffset? minExpiresUtc = null;
         foreach (var scheme in policy.AuthenticationSchemes)
         {
            var result = await context.AuthenticateAsync(scheme);
            if (result != null && result.Succeeded)
            {
               newPrincipal = SecurityHelper.MergeUserPrincipal(newPrincipal, result.Principal);
 
               if (minExpiresUtc is null || result.Properties?.ExpiresUtc < minExpiresUtc)
                  minExpiresUtc = result.Properties?.ExpiresUtc;
            }
         }
      }

      if (newPrincipal != null)
      {
         context.User = newPrincipal;
         var ticket = new AuthenticationTicket(newPrincipal, string.Join(";", policy.AuthenticationSchemes));
         // ExpiresUtc is the easiest property to reason about when dealing with multiple schemes
         // SignalR will use this property to evaluate auth expiration for long running connections
         ticket.Properties.ExpiresUtc = minExpiresUtc;
         return AuthenticateResult.Success(ticket);
      }
      else
      {
         context.User = new ClaimsPrincipal(new ClaimsIdentity());
         return AuthenticateResult.NoResult();
      }

      return context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult ?? DefaultAuthenticateResult(context);

      static AuthenticateResult DefaultAuthenticateResult(HttpContext context)
      {
         return (context.User?.Identity?.IsAuthenticated ?? false)
            ? AuthenticateResult.Success(new AuthenticationTicket(context.User, "context.User")) : AuthenticateResult.NoResult();
      }
   }

   public virtual async Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object? resource)
   { 
      var result = await _authorization.AuthorizeAsync(context.User, resource, policy);
      if (result.Succeeded)
         return PolicyAuthorizationResult.Success();
 
      // If authentication was successful, return forbidden, otherwise challenge
      return (authenticationResult.Succeeded) ? PolicyAuthorizationResult.Forbid(result.Failure) : PolicyAuthorizationResult.Challenge();
    }
}
//--------------------------Ʌ
```
=========================================================================================

```C#
//------------------------------------->>
public interface IAuthenticationHandler
{
   Task InitializeAsync(AuthenticationScheme scheme, HttpContext context);
   Task<AuthenticateResult> AuthenticateAsync();
   Task ChallengeAsync(AuthenticationProperties? properties);
   Task ForbidAsync(AuthenticationProperties? properties);
}
//-------------------------------------<<

//-------------------------------V
public class AuthenticationScheme
{
   public AuthenticationScheme(string name, string? displayName, Type handlerType)
   {
      if (!typeof(IAuthenticationHandler).IsAssignableFrom(handlerType))
         throw new ArgumentException("handlerType must implement IAuthenticationHandler.");
 
      Name = name;
      HandlerType = handlerType;
      DisplayName = displayName;
   }

   public string Name { get; }
   public string? DisplayName { get; }
   public Type HandlerType { get; }
}
//-------------------------------Ʌ

//--------------------------------------V
public class AuthenticationSchemeBuilder
{
   public AuthenticationSchemeBuilder(string name)
   {
      Name = name;
   }

   public string Name { get; }
   public string? DisplayName { get; set; }
   public Type? HandlerType { get; set; }

   public AuthenticationScheme Build()
   {
      if (HandlerType is null)
      {
         throw new InvalidOperationException($"{nameof(HandlerType)} must be configured to build an {nameof(AuthenticationScheme)}.");
      }
 
      return new AuthenticationScheme(Name, DisplayName, HandlerType);
   }
}
//--------------------------------------Ʌ

//-----------------------------------V
public class AuthenticationProperties
{
   internal const string IssuedUtcKey = ".issued";
   internal const string ExpiresUtcKey = ".expires";
   internal const string IsPersistentKey = ".persistent";
   internal const string RedirectUriKey = ".redirect";
   internal const string RefreshKey = ".refresh";
   internal const string UtcDateTimeFormat = "r";

   public AuthenticationProperties() : this(items: null, parameters: null) { }
   public AuthenticationProperties(IDictionary<string, string?> items) : this(items, parameters: null) { }

   public AuthenticationProperties(IDictionary<string, string?>? items, IDictionary<string, object?>? parameters)
   {
      Items = items ?? new Dictionary<string, string?>(StringComparer.Ordinal);
      Parameters = parameters ?? new Dictionary<string, object?>(StringComparer.Ordinal);
   }

   public DateTimeOffset? IssuedUtc { get; set; }
   public string? RedirectUri { get; set; }
   public bool IsPersistent { get; set; }   
   public IDictionary<string, object?> Parameters { get; }
   public IDictionary<string, string?> Items { get; }
   public DateTimeOffset? ExpiresUtc { get; set; }
   public bool? AllowRefresh { get; set; }

   public AuthenticationProperties Clone();
   public T? GetParameter<T>(string key);
   public string? GetString(string key);
   public void SetParameter<T>(string key, T value);
   public void SetString(string key, string? value);
   protected bool? GetBool(string key);
   protected DateTimeOffset? GetDateTimeOffset(string key);
   protected void SetBool(string key, bool? value);
   protected void SetDateTimeOffset(string key, DateTimeOffset? value);
}
//-----------------------------------Ʌ

//-----------------------------V
public class AuthenticateResult
{
   private static readonly AuthenticateResult _noResult = new() { None = true };
   
   protected AuthenticateResult() { }

   public bool Succeeded => Ticket != null;

   public AuthenticationTicket? Ticket { get; protected set; }

   public ClaimsPrincipal? Principal => Ticket?.Principal;

   public AuthenticationProperties? Properties { get; protected set; }

   public Exception? Failure { get; protected set; }

   public bool None { get; protected set; }

   public AuthenticateResult Clone();

   public static AuthenticateResult Success(AuthenticationTicket ticket)
   {
      return new AuthenticateResult() { Ticket = ticket, Properties = ticket.Properties };
   }

   public static AuthenticateResult NoResult() => _noResult;

   public static AuthenticateResult Fail(Exception failure)
   {
      return new AuthenticateResult() { Failure = failure };
   }

   public static AuthenticateResult Fail(Exception failure, AuthenticationProperties? properties)
   {
      return new AuthenticateResult() { Failure = failure, Properties = properties };
   }

   public static AuthenticateResult Fail(string failureMessage)
      => Fail(new AuthenticationFailureException(failureMessage));

   public static AuthenticateResult Fail(string failureMessage, AuthenticationProperties? properties)
      => Fail(new AuthenticationFailureException(failureMessage), properties);
}
//-----------------------------Ʌ

//-------------------------------V
public class AuthenticationTicket
{
   public AuthenticationTicket(ClaimsPrincipal principal, AuthenticationProperties? properties, string authenticationScheme)
   { 
      AuthenticationScheme = authenticationScheme;
      Principal = principal;
      Properties = properties ?? new AuthenticationProperties();
   }

   public AuthenticationTicket(ClaimsPrincipal principal, string authenticationScheme)
      : this(principal, properties: null, authenticationScheme: authenticationScheme) { }
   
   public string AuthenticationScheme { get; }

   public ClaimsPrincipal Principal { get; }

   public AuthenticationProperties Properties { get; }

   public AuthenticationTicket Clone()
   {
      var principal = new ClaimsPrincipal();
      foreach (var identity in Principal.Identities)
      {
         principal.AddIdentity(identity.Clone());
      }
      return new AuthenticationTicket(principal, Properties.Clone(), AuthenticationScheme);
   }
}
//-------------------------------Ʌ

//--------------------------------V
public class AuthenticationOptions
{
   private readonly IList<AuthenticationSchemeBuilder> _schemes = new List<AuthenticationSchemeBuilder>();

   public IEnumerable<AuthenticationSchemeBuilder> Schemes => _schemes;

   public IDictionary<string, AuthenticationSchemeBuilder> SchemeMap { get; } = new Dictionary<string, AuthenticationSchemeBuilder>(StringComparer.Ordinal);

   public void AddScheme(string name, Action<AuthenticationSchemeBuilder> configureBuilder)
   {
      if (SchemeMap.ContainsKey(name))
         throw new InvalidOperationException("Scheme already exists: " + name);
 
      var builder = new AuthenticationSchemeBuilder(name);
      configureBuilder(builder);
      _schemes.Add(builder);
      SchemeMap[name] = builder;
   }

   public void AddScheme<THandler>(string name, string? displayName) where THandler : IAuthenticationHandler
   {
      AddScheme(name, b =>
      {
         b.DisplayName = displayName;
         b.HandlerType = typeof(THandler);
      });
   }

   public string? DefaultScheme { get; set; }
   public string? DefaultAuthenticateScheme { get; set; }
   public string? DefaultSignInScheme { get; set; }
   public string? DefaultSignOutScheme { get; set; }
   public string? DefaultChallengeScheme { get; set; }
   public string? DefaultForbidScheme { get; set; }
   public bool RequireAuthenticatedSignIn { get; set; } = true;

   private bool? _disableAutoDefaultScheme;
   internal bool DisableAutoDefaultScheme
   {
      get
      {
         if (!_disableAutoDefaultScheme.HasValue)
            _disableAutoDefaultScheme = AppContext.TryGetSwitch("Microsoft.AspNetCore.Authentication.SuppressAutoDefaultScheme", out var enabled) && enabled;
 
         return _disableAutoDefaultScheme.Value;
      }
      set => _disableAutoDefaultScheme = value;
   }
}
//--------------------------------Ʌ

//--------------------------------------------------------------V
internal sealed class DefaultAuthenticationConfigurationProvider : IAuthenticationConfigurationProvider
{
   private readonly IConfiguration _configuration;
   private const string AuthenticationKey = "Authentication";

   public DefaultAuthenticationConfigurationProvider() : this(new ConfigurationManager()) { }

   public DefaultAuthenticationConfigurationProvider(IConfiguration configuration)
      => _configuration = configuration;

   public IConfiguration AuthenticationConfiguration => _configuration.GetSection(AuthenticationKey);
}
//--------------------------------------------------------------Ʌ

//--------------------------------V
public class AuthenticationBuilder
{
   public AuthenticationBuilder(IServiceCollection services)
   {
      Services = services;
   }

   public virtual IServiceCollection Services { get; }

   private AuthenticationBuilder AddSchemeHelper<TOptions, THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions)
      where TOptions : AuthenticationSchemeOptions, new()
      where THandler : class, IAuthenticationHandler
   {
      Services.Configure<AuthenticationOptions>(o =>
      {
         o.AddScheme(authenticationScheme, scheme =>
         {
            scheme.HandlerType = typeof(THandler);
            scheme.DisplayName = displayName;
         });
      });

      if (configureOptions != null)
      {
         Services.Configure(authenticationScheme, configureOptions);
      }

      Services.AddOptions<TOptions>(authenticationScheme).Validate(o =>
      {
         o.Validate(authenticationScheme);
         return true;
      });

      Services.AddTransient<THandler>();
      Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, PostConfigureAuthenticationSchemeOptions<TOptions>>());
      
      return this;
   }

   public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions)
      where TOptions : AuthenticationSchemeOptions, new()
      where THandler : AuthenticationHandler<TOptions>
      => AddSchemeHelper<TOptions, THandler>(authenticationScheme, displayName, configureOptions);

   public virtual AuthenticationBuilder AddScheme<TOptions, THandler>(string authenticationScheme, Action<TOptions>? configureOptions)
      where TOptions : AuthenticationSchemeOptions, new()
      where THandler : AuthenticationHandler<TOptions>
      => AddScheme<TOptions, THandler>(authenticationScheme, displayName: null, configureOptions: configureOptions);
   
   public virtual AuthenticationBuilder AddRemoteScheme<TOptions, THandler>(string authenticationScheme, string? displayName, Action<TOptions>? configureOptions)
      where TOptions : RemoteAuthenticationOptions, new()
      where THandler : RemoteAuthenticationHandler<TOptions>
   {
      Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, EnsureSignInScheme<TOptions>>());
      return AddScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions: configureOptions);
   }

   public virtual AuthenticationBuilder AddPolicyScheme(string authenticationScheme, string? displayName, Action<PolicySchemeOptions> configureOptions)
      => AddSchemeHelper<PolicySchemeOptions, PolicySchemeHandler>(authenticationScheme, displayName, configureOptions);

   private sealed class EnsureSignInScheme<TOptions> : IPostConfigureOptions<TOptions> where TOptions : RemoteAuthenticationOptions
   {
      private readonly AuthenticationOptions _authOptions;
 
      public EnsureSignInScheme(IOptions<AuthenticationOptions> authOptions)
      {
         _authOptions = authOptions.Value;
      }
 
      public void PostConfigure(string? name, TOptions options)
      {
         options.SignInScheme ??= _authOptions.DefaultSignInScheme ?? _authOptions.DefaultScheme;
      }
   }
 
   // Set TimeProvider from DI on all options instances, if not already set by tests.
   private sealed class PostConfigureAuthenticationSchemeOptions<TOptions> : IPostConfigureOptions<TOptions>
      where TOptions : AuthenticationSchemeOptions
   {
      public PostConfigureAuthenticationSchemeOptions(TimeProvider timeProvider)
      {
            TimeProvider = timeProvider;
      }
 
      private TimeProvider TimeProvider { get; }
 
      public void PostConfigure(string? name, TOptions options)
      {
         options.TimeProvider ??= TimeProvider;
      }
   }
}
//--------------------------------Ʌ

//--------------------------------V
public class AuthenticationService : IAuthenticationService
{
   private HashSet<ClaimsPrincipal>? _transformCache;

   public AuthenticationService(IAuthenticationSchemeProvider schemes, IAuthenticationHandlerProvider handlers, IClaimsTransformation transform, IOptions<AuthenticationOptions> options)
   {
      Schemes = schemes;
      Handlers = handlers;
      Transform = transform;
      Options = options.Value;
   }

   public IAuthenticationSchemeProvider Schemes { get; }
   public IAuthenticationHandlerProvider Handlers { get; }
   public IClaimsTransformation Transform { get; }
   public AuthenticationOptions Options { get; }

   public virtual async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
   {
      if (scheme == null)
      {
         var defaultScheme = await Schemes.GetDefaultAuthenticateSchemeAsync();
         scheme = defaultScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }

      var handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
         throw await CreateMissingHandlerException(scheme);
 
      // Handlers should not return null, but we'll be tolerant of null values for legacy reasons.
      var result = (await handler.AuthenticateAsync()) ?? AuthenticateResult.NoResult();
 
      if (result.Succeeded)
      {
         var principal = result.Principal!;
         var doTransform = true;
         _transformCache ??= new HashSet<ClaimsPrincipal>();
         if (_transformCache.Contains(principal))
            doTransform = false;
 
         if (doTransform)
         {
            principal = await Transform.TransformAsync(principal);
            _transformCache.Add(principal);
         }
         return AuthenticateResult.Success(new AuthenticationTicket(principal, result.Properties, result.Ticket!.AuthenticationScheme));
      }
      return result;
   }

   public virtual async Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
   {
      if (scheme == null)
      {
         var defaultChallengeScheme = await Schemes.GetDefaultChallengeSchemeAsync();
         scheme = defaultChallengeScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultChallengeScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      var handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
      {
         throw await CreateMissingHandlerException(scheme);
      }
 
      await handler.ChallengeAsync(properties);
   }

   public virtual async Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
   {
      if (scheme == null)
      {
         var defaultForbidScheme = await Schemes.GetDefaultForbidSchemeAsync();
         scheme = defaultForbidScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultForbidScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      var handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
      {
         throw await CreateMissingHandlerException(scheme);
      }
 
      await handler.ForbidAsync(properties);
   }

   public virtual async Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
   {
      if (Options.RequireAuthenticatedSignIn)
      {
         if (principal.Identity == null)
                throw new InvalidOperationException("SignInAsync when principal.Identity == null is not allowed when AuthenticationOptions.RequireAuthenticatedSignIn is true.");
            
         if (!principal.Identity.IsAuthenticated)
                throw new InvalidOperationException("SignInAsync when principal.Identity.IsAuthenticated is false is not allowed when AuthenticationOptions.RequireAuthenticatedSignIn is true.");
      }
 
      if (scheme == null)
      {
         var defaultScheme = await Schemes.GetDefaultSignInSchemeAsync();
         scheme = defaultScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultSignInScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      var handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
      {
         throw await CreateMissingSignInHandlerException(scheme);
      }
 
      var signInHandler = handler as IAuthenticationSignInHandler;
      if (signInHandler == null)
      {
         throw await CreateMismatchedSignInHandlerException(scheme, handler);
      }
 
      await signInHandler.SignInAsync(principal, properties);
   }

   public virtual async Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
   {
      if (scheme == null)
      {
         var defaultScheme = await Schemes.GetDefaultSignOutSchemeAsync();
         scheme = defaultScheme?.Name;
         if (scheme == null)
         {
            throw new InvalidOperationException($"No authenticationScheme was specified, and there was no DefaultSignOutScheme found. The default schemes can be set using either AddAuthentication(string defaultScheme) or AddAuthentication(Action<AuthenticationOptions> configureOptions).");
         }
      }
 
      var handler = await Handlers.GetHandlerAsync(context, scheme);
      if (handler == null)
      {
         throw await CreateMissingSignOutHandlerException(scheme);
      }
 
      var signOutHandler = handler as IAuthenticationSignOutHandler;
      if (signOutHandler == null)
      {
         throw await CreateMismatchedSignOutHandlerException(scheme, handler);
      }
 
      await signOutHandler.SignOutAsync(properties);
   }

   private async Task<Exception> CreateMissingHandlerException(string scheme)
   {
      var schemes = string.Join(", ", (await Schemes.GetAllSchemesAsync()).Select(sch => sch.Name));
 
      var footer = $" Did you forget to call AddAuthentication().Add[SomeAuthHandler](\"{scheme}\",...)?";
 
      if (string.IsNullOrEmpty(schemes))
            return new InvalidOperationException($"No authentication handlers are registered." + footer);
 
      return new InvalidOperationException($"No authentication handler is registered for the scheme '{scheme}'. The registered schemes are: {schemes}." + footer);
   }

   private async Task<string> GetAllSignInSchemeNames()
   {
      return string.Join(", ", (await Schemes.GetAllSchemesAsync())
         .Where(sch => typeof(IAuthenticationSignInHandler).IsAssignableFrom(sch.HandlerType))
         .Select(sch => sch.Name));
   }
 
   private async Task<Exception> CreateMissingSignInHandlerException(string scheme)
   {
      var schemes = await GetAllSignInSchemeNames();
 
      // CookieAuth is the only implementation of sign-in.
      var footer = $" Did you forget to call AddAuthentication().AddCookie(\"{scheme}\",...)?";
 
      if (string.IsNullOrEmpty(schemes))
      {
         return new InvalidOperationException($"No sign-in authentication handlers are registered." + footer);
      }
 
      return new InvalidOperationException($"No sign-in authentication handler is registered for the scheme '{scheme}'. The registered sign-in schemes are: {schemes}." + footer);
   }

   private async Task<Exception> CreateMismatchedSignInHandlerException(string scheme, IAuthenticationHandler handler)
   {
      var schemes = await GetAllSignInSchemeNames();
 
      var mismatchError = $"The authentication handler registered for scheme '{scheme}' is '{handler.GetType().Name}' which cannot be used for SignInAsync. ";
 
      if (string.IsNullOrEmpty(schemes))
      {
         // CookieAuth is the only implementation of sign-in.
         return new InvalidOperationException(mismatchError + $"Did you forget to call AddAuthentication().AddCookie(\"Cookies\") and SignInAsync(\"Cookies\",...)?");
      }
 
      return new InvalidOperationException(mismatchError + $"The registered sign-in schemes are: {schemes}.");
   }
 
   private async Task<string> GetAllSignOutSchemeNames()
   {
      return string.Join(", ", (await Schemes.GetAllSchemesAsync())
         .Where(sch => typeof(IAuthenticationSignOutHandler).IsAssignableFrom(sch.HandlerType))
         .Select(sch => sch.Name));
   }

   private async Task<Exception> CreateMissingSignOutHandlerException(string scheme)
   {
      var schemes = await GetAllSignOutSchemeNames();
 
      var footer = $" Did you forget to call AddAuthentication().AddCookie(\"{scheme}\",...)?";
 
      if (string.IsNullOrEmpty(schemes))
      {
         // CookieAuth is the most common implementation of sign-out, but OpenIdConnect and WsFederation also support it.
         return new InvalidOperationException($"No sign-out authentication handlers are registered." + footer);
      }
 
      return new InvalidOperationException( $"No sign-out authentication handler is registered for the scheme '{scheme}'. The registered sign-out schemes are: {schemes}." + footer);
   }
 
   private async Task<Exception> CreateMismatchedSignOutHandlerException(string scheme, IAuthenticationHandler handler)
   {
      var schemes = await GetAllSignOutSchemeNames();
 
      var mismatchError = $"The authentication handler registered for scheme '{scheme}' is '{handler.GetType().Name}' which cannot be used for {nameof(SignOutAsync)}. ";
 
      if (string.IsNullOrEmpty(schemes))
      {
         // CookieAuth is the most common implementation of sign-out, but OpenIdConnect and WsFederation also support it.
         return new InvalidOperationException(mismatchError + $"Did you forget to call AddAuthentication().AddCookie(\"Cookies\") and {nameof(SignOutAsync)}(\"Cookies\",...)?");
      }
 
      return new InvalidOperationException(mismatchError + $"The registered sign-out schemes are: {schemes}.");
   }
}
//--------------------------------Ʌ

//-----------------------------------V
public class NoopClaimsTransformation : IClaimsTransformation
{
    public virtual Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        return Task.FromResult(principal);
    }
}
//-----------------------------------Ʌ

//----------------------------------------V
public class AuthenticationHandlerProvider : IAuthenticationHandlerProvider
{
   public AuthenticationHandlerProvider(IAuthenticationSchemeProvider schemes)
   {
      Schemes = schemes;
   }

   public IAuthenticationSchemeProvider Schemes { get; }

   private readonly Dictionary<string, IAuthenticationHandler> _handlerMap = new Dictionary<string, IAuthenticationHandler>(StringComparer.Ordinal);

   public async Task<IAuthenticationHandler?> GetHandlerAsync(HttpContext context, string authenticationScheme)
   {
      if (_handlerMap.TryGetValue(authenticationScheme, out var value))
         return value;
 
      var scheme = await Schemes.GetSchemeAsync(authenticationScheme);
      if (scheme == null)
         return null;

      var handler = (context.RequestServices.GetService(scheme.HandlerType) ??
         ActivatorUtilities.CreateInstance(context.RequestServices, scheme.HandlerType))
         as IAuthenticationHandler;

      if (handler != null)
      {
         await handler.InitializeAsync(scheme, context);
         _handlerMap[authenticationScheme] = handler;
      }

      return handler;
   }
}
//----------------------------------------Ʌ

//---------------------------------------V
public class AuthenticationSchemeProvider : IAuthenticationSchemeProvider
{
   public AuthenticationSchemeProvider(IOptions<AuthenticationOptions> options) : this(options, new Dictionary<string, AuthenticationScheme>(StringComparer.Ordinal)) { }

   protected AuthenticationSchemeProvider(IOptions<AuthenticationOptions> options, IDictionary<string, AuthenticationScheme> schemes)
   {
      _options = options.Value;
 
      _schemes = schemes ?? throw new ArgumentNullException(nameof(schemes));
      _requestHandlers = new List<AuthenticationScheme>();
 
      foreach (var builder in _options.Schemes)
      {
         var scheme = builder.Build();
         AddScheme(scheme);
      }
   }

   private readonly AuthenticationOptions _options;
   private readonly object _lock = new object();
 
   private readonly IDictionary<string, AuthenticationScheme> _schemes;
   private readonly List<AuthenticationScheme> _requestHandlers;
   private static readonly Task<AuthenticationScheme?> _nullScheme = Task.FromResult<AuthenticationScheme?>(null);
   private Task<AuthenticationScheme?> _autoDefaultScheme = _nullScheme;
 
   // Used as a safe return value for enumeration apis
   private IEnumerable<AuthenticationScheme> _schemesCopy = Array.Empty<AuthenticationScheme>();
   private IEnumerable<AuthenticationScheme> _requestHandlersCopy = Array.Empty<AuthenticationScheme>();

   private Task<AuthenticationScheme?> GetDefaultSchemeAsync()
      => _options.DefaultScheme != null ? GetSchemeAsync(_options.DefaultScheme) : _autoDefaultScheme;

   public virtual Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync()
      => _options.DefaultAuthenticateScheme != null ? GetSchemeAsync(_options.DefaultAuthenticateScheme) : GetDefaultSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync()
      => _options.DefaultChallengeScheme != null ? GetSchemeAsync(_options.DefaultChallengeScheme) : GetDefaultSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync()
      => _options.DefaultForbidScheme != null ? GetSchemeAsync(_options.DefaultForbidScheme) : GetDefaultChallengeSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync()
      => _options.DefaultSignInScheme != null ? GetSchemeAsync(_options.DefaultSignInScheme) : GetDefaultSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync()
      => _options.DefaultSignOutScheme != null ? GetSchemeAsync(_options.DefaultSignOutScheme) : GetDefaultSignInSchemeAsync();

   public virtual Task<AuthenticationScheme?> GetSchemeAsync(string name)
      => Task.FromResult(_schemes.TryGetValue(name, out var scheme) ? scheme : null);
   
   public virtual Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync()
      => Task.FromResult(_requestHandlersCopy);
   
   public virtual bool TryAddScheme(AuthenticationScheme scheme)
   {
      if (_schemes.ContainsKey(scheme.Name))
         return false;

      lock (_lock)
      {
         if (_schemes.ContainsKey(scheme.Name))
            return false;

         if (typeof(IAuthenticationRequestHandler).IsAssignableFrom(scheme.HandlerType))
         {
            _requestHandlers.Add(scheme);
            _requestHandlersCopy = _requestHandlers.ToArray();
         }
         _schemes[scheme.Name] = scheme;
         _schemesCopy = _schemes.Values.ToArray();
         CheckAutoDefaultScheme();
 
         return true;
      }
   }

   public virtual void AddScheme(AuthenticationScheme scheme)
   {
      if (_schemes.ContainsKey(scheme.Name))
         throw new InvalidOperationException("Scheme already exists: " + scheme.Name);

      lock (_lock)
      {
         if (!TryAddScheme(scheme))
            throw new InvalidOperationException("Scheme already exists: " + scheme.Name);
      }
   }

   public virtual void RemoveScheme(string name)
   {
      if (!_schemes.TryGetValue(name, out _))      
         return;
        
      lock (_lock)
      {
         if (_schemes.TryGetValue(name, out var scheme))
         {
            if (_requestHandlers.Remove(scheme))      
               _requestHandlersCopy = _requestHandlers.ToArray();
            
            _schemes.Remove(name);
            _schemesCopy = _schemes.Values.ToArray();
            CheckAutoDefaultScheme();
         }
      }
   }

   public virtual Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync() => Task.FromResult(_schemesCopy);

   private void CheckAutoDefaultScheme()
   {
      if (!_options.DisableAutoDefaultScheme)
      {
         if (_schemes.Count == 1)
            _autoDefaultScheme = Task.FromResult<AuthenticationScheme?>(_schemesCopy.First());   
         else
            _autoDefaultScheme = _nullScheme;
      }
   }
}
//---------------------------------------Ʌ
```

========================================================================================================================

**Authorization**

```C#
//--------------------------------------------V
internal sealed class AuthorizationPolicyCache : IDisposable
{
   private readonly DataSourceDependentCache<ConcurrentDictionary<Endpoint, AuthorizationPolicy>> _policyCache;

   public AuthorizationPolicyCache(EndpointDataSource dataSource)
   {
      // We cache AuthorizationPolicy instances per-Endpoint for performance, but we want to wipe out
      // that cache if the endpoints change so that we don't allow unbounded memory growth.
      _policyCache = new DataSourceDependentCache<ConcurrentDictionary<Endpoint, AuthorizationPolicy>>(dataSource, (_) =>
      {
         // We don't eagerly fill this cache because there's no real reason to.
         eturn new ConcurrentDictionary<Endpoint, AuthorizationPolicy>();
      });
      _policyCache.EnsureInitialized();
   }

   public AuthorizationPolicy? Lookup(Endpoint endpoint)
   {
      _policyCache.Value!.TryGetValue(endpoint, out var policy);
      return policy;
   }
 
   public void Store(Endpoint endpoint, AuthorizationPolicy policy)
   {
      _policyCache.Value![endpoint] = policy;
   }
 
   public void Dispose()
   {
       _policyCache.Dispose();
   }
}
//--------------------------------------------Ʌ

//--------------------------------------V
public class DefaultAuthorizationService : IAuthorizationService
{
   private readonly AuthorizationOptions _options;
   private readonly IAuthorizationHandlerContextFactory _contextFactory;
   private readonly IAuthorizationHandlerProvider _handlers;
   private readonly IAuthorizationEvaluator _evaluator;
   private readonly IAuthorizationPolicyProvider _policyProvider;
   private readonly ILogger _logger;

   public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IAuthorizationHandlerProvider handlers, ILogger<DefaultAuthorizationService> logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator, IOptions<AuthorizationOptions> options)
   {
      _options = options.Value;
      _handlers = handlers;
      _policyProvider = policyProvider;
      _logger = logger;
      _evaluator = evaluator;
      _contextFactory = contextFactory;
   }

   public virtual async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements)
   {
      var authContext = _contextFactory.CreateContext(requirements, user, resource);
      var handlers = await _handlers.GetHandlersAsync(authContext).ConfigureAwait(false);
      foreach (var handler in handlers)
      {
         await handler.HandleAsync(authContext).ConfigureAwait(false);
         if (!_options.InvokeHandlersAfterFailure && authContext.HasFailed)
         {
            break;
         }
      }
 
      var result = _evaluator.Evaluate(authContext);
      if (result.Succeeded)
      {
         _logger.UserAuthorizationSucceeded();
      }
      else
      {
         _logger.UserAuthorizationFailed(result.Failure);
      }
      
      return result;
   }

   public virtual async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName)
   { 
      var policy = await _policyProvider.GetPolicyAsync(policyName).ConfigureAwait(false);
      if (policy == null)
         throw new InvalidOperationException($"No policy found: {policyName}.");

      return await this.AuthorizeAsync(user, resource, policy).ConfigureAwait(false);
   }
}
//--------------------------------------Ʌ

//-----------------------------------------------V
public class AuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
   public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
   {
      if (authorizeResult.Succeeded)
      {
         return next(context);
      }

      return Handle();

      async Task Handle()
      {
         if (authorizeResult.Challenged)
         {
            if (policy.AuthenticationSchemes.Count > 0)
            {
               foreach (var scheme in policy.AuthenticationSchemes)
               {
                  await context.ChallengeAsync(scheme);
               }
            }
            else
            {
               await context.ChallengeAsync();
            }
         }
         else if (authorizeResult.Forbidden)
         {
            if (policy.AuthenticationSchemes.Count > 0)
            {
               foreach (var scheme in policy.AuthenticationSchemes)
               {
                  await context.ForbidAsync(scheme);
               }
            }
            else
            {
               await context.ForbidAsync();
            }
         }
      }
   }
}
//-----------------------------------------------Ʌ

//---------------------------------------------V
public class DefaultAuthorizationPolicyProvider : IAuthorizationPolicyProvider
{
   private readonly AuthorizationOptions _options;
   private Task<AuthorizationPolicy>? _cachedDefaultPolicy;
   private Task<AuthorizationPolicy?>? _cachedFallbackPolicy;

   public DefaultAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options)
   {
      _options = options.Value;
   }

   public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
   {
      if (_cachedDefaultPolicy == null || _cachedDefaultPolicy.Result != _options.DefaultPolicy)
      {
         _cachedDefaultPolicy = Task.FromResult(_options.DefaultPolicy);
      }
 
      return _cachedDefaultPolicy;
   }

   public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
   {
      if (_cachedFallbackPolicy == null || _cachedFallbackPolicy.Result != _options.FallbackPolicy)
      {
         _cachedFallbackPolicy = Task.FromResult(_options.FallbackPolicy);
      }
 
      return _cachedFallbackPolicy;
   }

   public virtual Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
   {
      // MVC caches policies specifically for this class, so this method MUST return the same policy per
      // policyName for every request or it could allow undesired access. It also must return synchronously.
      // A change to either of these behaviors would require shipping a patch of MVC as well.
      return _options.GetPolicyTask(policyName);
   }

   public virtual bool AllowsCachingPolicies => GetType() == typeof(DefaultAuthorizationPolicyProvider);
}
//---------------------------------------------Ʌ

//-------------------------------V
public class AuthorizationOptions
{
   private static readonly Task<AuthorizationPolicy?> _nullPolicyTask = Task.FromResult<AuthorizationPolicy?>(null);

   private Dictionary<string, Task<AuthorizationPolicy?>> PolicyMap { get; } = new Dictionary<string, Task<AuthorizationPolicy?>>(StringComparer.OrdinalIgnoreCase);

   public bool InvokeHandlersAfterFailure { get; set; } = true;

   public AuthorizationPolicy DefaultPolicy { get; set; } = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

   public AuthorizationPolicy? FallbackPolicy { get; set; }

   public void AddPolicy(string name, AuthorizationPolicy policy)
   { 
      PolicyMap[name] = Task.FromResult<AuthorizationPolicy?>(policy);
   }

   public void AddPolicy(string name, Action<AuthorizationPolicyBuilder> configurePolicy)
   {
      var policyBuilder = new AuthorizationPolicyBuilder();
      configurePolicy(policyBuilder);
      PolicyMap[name] = Task.FromResult<AuthorizationPolicy?>(policyBuilder.Build());
   }

   public AuthorizationPolicy? GetPolicy(string name)
   { 
      if (PolicyMap.TryGetValue(name, out var value))
      {
         return value.Result;
      }
 
      return null;
   }

   internal Task<AuthorizationPolicy?> GetPolicyTask(string name)
   { 
      if (PolicyMap.TryGetValue(name, out var value))
      {
         return value;
      }
 
      return _nullPolicyTask;
   }
}
//-------------------------------Ʌ

//----------------------------------------------V
public class DefaultAuthorizationHandlerProvider : IAuthorizationHandlerProvider
{
   private readonly Task<IEnumerable<IAuthorizationHandler>> _handlersTask;

   public DefaultAuthorizationHandlerProvider(IEnumerable<IAuthorizationHandler> handlers)
   { 
      _handlersTask = Task.FromResult(handlers);
   }

   public Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync(AuthorizationHandlerContext context)
      => _handlersTask;
}
//----------------------------------------------Ʌ

//----------------------------------------V
public class DefaultAuthorizationEvaluator : IAuthorizationEvaluator
{
   public AuthorizationResult Evaluate(AuthorizationHandlerContext context)
      => context.HasSucceeded
         ? AuthorizationResult.Success()
         : AuthorizationResult.Failed(context.HasFailed
            ? AuthorizationFailure.Failed(context.FailureReasons)
            : AuthorizationFailure.Failed(context.PendingRequirements));
}
//----------------------------------------Ʌ

//----------------------------------------------------V
public class DefaultAuthorizationHandlerContextFactory : IAuthorizationHandlerContextFactory
{
   public virtual AuthorizationHandlerContext CreateContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object? resource)
   {
      return new AuthorizationHandlerContext(requirements, user, resource);
   }
}
//----------------------------------------------------Ʌ

//------------------------------------------V
public class PassThroughAuthorizationHandler : IAuthorizationHandler
{
   private readonly AuthorizationOptions _options;

   public PassThroughAuthorizationHandler() : this(Options.Create(new AuthorizationOptions())) { }

   public PassThroughAuthorizationHandler(IOptions<AuthorizationOptions> options)
      => _options = options.Value;

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
//------------------------------------------Ʌ
```