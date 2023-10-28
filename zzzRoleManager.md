```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        // ...

        services.AddIdentityCore<AppUser>(opts => // opts is IdentityOptions
        {
            opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
        })
        .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
        .AddSignInManager();
        .AddRoles<AppRole>();  // <-----------------------------------------------------

        services.AddSingleton<IRoleStore<AppRole>, RoleStore>();
        services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>, AppUserClaimsPrincipalFactory>();
    }
    // ...
}
//------------------Ʌ

//--------------------------V
public class IdentityBuilder
{
    // ...

    public virtual IdentityBuilder AddRoles<TRole>()
    {
        RoleType = typeof(TRole);
        AddRoleValidator<RoleValidator<TRole>>();
        Services.TryAddScoped<RoleManager<TRole>>();
        Services.AddScoped(typeof(IUserClaimsPrincipalFactory<>).MakeGenericType(UserType), typeof(UserClaimsPrincipalFactory<,>).MakeGenericType(UserType, RoleType));
        return this;
    }

    public virtual IdentityBuilder AddRoleValidator<TRole>() where TRole : class
    {
        if (RoleType == null)
            throw new InvalidOperationException(Resources.NoRoleType);
        
        return AddScoped(typeof(IRoleValidator<>).MakeGenericType(RoleType), typeof(TRole));
    }

    public virtual async Task<IdentityResult> ValidateAsync(RoleManager<TRole> manager, TRole role)
    {
        var errors = await ValidateRoleName(manager, role).ConfigureAwait(false);
        
        if (errors?.Count > 0)
        {
            return IdentityResult.Failed(errors);
        }

        return IdentityResult.Success;
    }

    private async Task<List<IdentityError>?> ValidateRoleName(RoleManager<TRole> manager, TRole role)
    {
        List<IdentityError>? errors = null;
        var roleName = await manager.GetRoleNameAsync(role).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(roleName))
        {
            errors ??= new List<IdentityError>();
            errors.Add(Describer.InvalidRoleName(roleName));
        }
        else
        {
            var owner = await manager.FindByNameAsync(roleName).ConfigureAwait(false);

            if (owner != null && !string.Equals(await manager.GetRoleIdAsync(owner).ConfigureAwait(false), await manager.GetRoleIdAsync(role).ConfigureAwait(false)))
            {
                errors ??= new List<IdentityError>();
                errors.Add(Describer.DuplicateRoleName(roleName));
            }
        }
 
        return errors;
    }
}
//--------------------------Ʌ

//-------------------------------V
public class RoleValidator<TRole> : IRoleValidator<TRole>
{
    public RoleValidator(IdentityErrorDescriber? errors = null)
    {
        Describer = errors ?? new IdentityErrorDescriber();
    }

    private IdentityErrorDescriber Describer { get; set; }


}
//-------------------------------Ʌ
```

```C#
//----------------------V
public class SignInModel : PageModel
{
    public SignInModel(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
    {
        UserManager = userManager;
        SignInManager = signInManager;
    }

    public UserManager<AppUser> UserManager { get; set; }
    public SignInManager<AppUser> SignInManager { get; set; }

    // ...

    public async Task<ActionResult> OnPost(string username, [FromQuery] string returnUrl)
    {
        AppUser user = await UserManager.FindByEmailAsync(username);

        await SignInManager.SignInAsync(user, false);  // <--------------------------s1

        // ...
    }
}
//----------------------Ʌ
```



## `RoleManager`

```C#
//-----------------------------V
public class RoleManager<TRole> : IDisposable where TRole : class
{
    private bool _disposed;

    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    public RoleManager(
        IRoleStore<TRole> store,  // <--------------------------------------------
        IEnumerable<IRoleValidator<TRole>> roleValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        ILogger<RoleManager<TRole>> logger)
    {
        Store = store;
        KeyNormalizer = keyNormalizer;
        ErrorDescriber = errors;
        Logger = logger;
 
        if (roleValidators != null)
        {
            foreach (var v in roleValidators)
            {
                RoleValidators.Add(v);  // <----------------------------
            }
        }
    }

    protected IRoleStore<TRole> Store { get; private set; }  // <-------------------

    public virtual ILogger Logger { get; set; }  

    public IList<IRoleValidator<TRole>> RoleValidators { get; } = new List<IRoleValidator<TRole>>();  // <------------------------------

    public IdentityErrorDescriber ErrorDescriber { get; set; }

    public ILookupNormalizer KeyNormalizer { get; set; }

    public virtual IQueryable<TRole> Roles {  // <---------------------------
        get
        {
            var queryableStore = Store as IQueryableRoleStore<TRole>;
            if (queryableStore == null)
            {
                throw new NotSupportedException(Resources.StoreNotIQueryableRoleStore);
            }
            return queryableStore.Roles;
        }
    }

    public virtual bool SupportsQueryableRoles
    {
        get {
            return Store is IQueryableRoleStore<TRole>;
        }
    }

    public virtual bool SupportsRoleClaims
    {
        get
        {
            return Store is IRoleClaimStore<TRole>;
        }
    }

    public virtual async Task<IdentityResult> CreateAsync(TRole role)
    {
        var result = await ValidateRoleAsync(role).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }
        await UpdateNormalizedRoleNameAsync(role).ConfigureAwait(false);
        result = await Store.CreateAsync(role, CancellationToken).ConfigureAwait(false);
        return result;
    }

    public virtual async Task UpdateNormalizedRoleNameAsync(TRole role)
    {
        var name = await GetRoleNameAsync(role).ConfigureAwait(false);
        await Store.SetNormalizedRoleNameAsync(role, NormalizeKey(name), CancellationToken).ConfigureAwait(false);
    }

    public virtual Task<IdentityResult> UpdateAsync(TRole role)
    {
        return UpdateRoleAsync(role);
    }

    public virtual Task<IdentityResult> DeleteAsync(TRole role)
    {
        return Store.DeleteAsync(role, CancellationToken);
    }

    public virtual async Task<bool> RoleExistsAsync(string roleName)
    {
        return await FindByNameAsync(roleName).ConfigureAwait(false) != null;
    }

    public virtual string? NormalizeKey(string? key)
    {
        return (KeyNormalizer == null) ? key : KeyNormalizer.NormalizeName(key);
    }

    public virtual Task<TRole?> FindByIdAsync(string roleId)
    {
        return Store.FindByIdAsync(roleId, CancellationToken);
    }

    public virtual Task<string?> GetRoleNameAsync(TRole role)
    {
        return Store.GetRoleNameAsync(role, CancellationToken);
    }

    public virtual async Task<IdentityResult> SetRoleNameAsync(TRole role, string? name)
    { 
        await Store.SetRoleNameAsync(role, name, CancellationToken).ConfigureAwait(false);
        await UpdateNormalizedRoleNameAsync(role).ConfigureAwait(false);
        return IdentityResult.Success;
    }

    public virtual Task<string> GetRoleIdAsync(TRole role)
    {
        return Store.GetRoleIdAsync(role, CancellationToken);
    }

    public virtual Task<TRole?> FindByNameAsync(string roleName)
    {
        return Store.FindByNameAsync(NormalizeKey(roleName), CancellationToken);
    }

    public virtual async Task<IdentityResult> AddClaimAsync(TRole role, Claim claim)
    {
        var claimStore = GetClaimStore();

        await claimStore.AddClaimAsync(role, claim, CancellationToken).ConfigureAwait(false);
        return await UpdateRoleAsync(role).ConfigureAwait(false);
    }

    public virtual async Task<IdentityResult> RemoveClaimAsync(TRole role, Claim claim)
    {
        var claimStore = GetClaimStore();
 
        await claimStore.RemoveClaimAsync(role, claim, CancellationToken).ConfigureAwait(false);
        return await UpdateRoleAsync(role).ConfigureAwait(false);
    }

    public virtual Task<IList<Claim>> GetClaimsAsync(TRole role)
    {
        var claimStore = GetClaimStore();
        return claimStore.GetClaimsAsync(role, CancellationToken);
    }

    protected virtual async Task<IdentityResult> UpdateRoleAsync(TRole role) // <----------------------
    {
        var result = await ValidateRoleAsync(role).ConfigureAwait(false);  // <--------------validations only apply on Create, Update, not on Delete
        if (!result.Succeeded)
        {
            return result;
        }
        await UpdateNormalizedRoleNameAsync(role).ConfigureAwait(false);
        return await Store.UpdateAsync(role, CancellationToken).ConfigureAwait(false);
    }

    protected virtual async Task<IdentityResult> ValidateRoleAsync(TRole role)
    {
        List<IdentityError>? errors = null;
        foreach (var v in RoleValidators)
        {
            var result = await v.ValidateAsync(this, role).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                errors ??= new List<IdentityError>();
                errors.AddRange(result.Errors);
            }
        }
        if (errors?.Count > 0)
        {
            if (Logger.IsEnabled(LogLevel.Warning))
            {
                Logger.LogWarning(LoggerEventIds.RoleValidationFailed, "Role {roleId} validation failed: {errors}.", await GetRoleIdAsync(role).ConfigureAwait(false), string.Join(";", errors.Select(e => e.Code)));
            }
            return IdentityResult.Failed(errors);
        }
        return IdentityResult.Success;
    }

    private IRoleClaimStore<TRole> GetClaimStore()  // <----------------------------------
    {
        var cast = Store as IRoleClaimStore<TRole>;
        if (cast == null)
        {
            throw new NotSupportedException(Resources.StoreNotIRoleClaimStore);
        }
        return cast;
    }
}
//-----------------------------Ʌ
```

```C#
//------------------------------------>>
public interface IRoleValidator<TRole> where TRole : class
{
    Task<IdentityResult> ValidateAsync(RoleManager<TRole> manager, TRole role);
}
//------------------------------------<<
```