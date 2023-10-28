3-Introduction to Identity
==============================

```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<ILookupNormalizer, Normalizer>();
        services.AddSingleton<IUserStore<AppUser>, UserStore>();  // <--------------------------UserStore will be register into UserManager<TUser>'s constructor
        services.AddSingleton<IUserValidator<AppUser>, EmailValidator>();

        // AddIdentityCore registers AppUser as TUser to built-in types such as UserManager<TUser>, UserValidator<TUser> etc
        services.AddIdentityCore<AppUser>(opts => {  // opts is IdentityOptions   
            opts.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyz";
            opts.User.RequireUniqueEmail = true;
        });
        
        services.AddIdentityCore<AppUser>(opts => // opts is IdentityOptions
        {  
            /* configure UserValidator<TUser> which is registered as IUserValidator<TUser>
      
            opts.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyz";
            opts.User.RequireUniqueEmail = true;  // check source code i1

            */

            // opts.Tokens is TokenOptions
            opts.Tokens.EmailConfirmationTokenProvider = "SimpleEmail";
            opts.Tokens.ChangeEmailTokenProvider = "SimpleEmail";
            //
            
            //
            opts.Password.RequireNonAlphanumeric = false;
            opts.Password.RequireLowercase = false;
            opts.Password.RequireUppercase = false;
            opts.Password.RequireDigit = false;
            opts.Password.RequiredLength = 8;
            //
        })
        // AddTokenProvider will register service for you automatically, so you don't need to explicit register it
        // such as `services.AddSingleton<IUserTwoFactorTokenProvider, xxx>();` check source code t1
        // provider name such as "SimpleEmail" is just setup ProviderMap which is Dictionary<string, TokenProviderDescriptor> 
        .AddTokenProvider<EmailConfirmationTokenGenerator>("SimpleEmail")
        .AddTokenProvider<PhoneConfirmationTokenGenerator>(TokenOptions.DefaultPhoneProvider);  // DefaultPhoneProvider = "Phone";

        // ...
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {

        app.UseStaticFiles();
        app.UseAuthentication();
        app.UseRouting();
        app.UseMiddleware<RoleMemberships>();
        app.UseAuthorization();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapRazorPages();
            endpoints.MapDefaultControllerRoute();
        });
    }
}
//------------------Ʌ
```

```C#
//------------------V
public class AppUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    public string UserName { get; set; }

    public string NormalizedUserName { get; set; }

    public string EmailAddress { get; set; }
    public string NormalizedEmailAddress { get; set; }
    public bool EmailAddressConfirmed { get; set; }

    public string PhoneNumber { get; set; }
    public bool PhoneNumberConfirmed { get; set; }

    public string FavoriteFood { get; set; }
    public string Hobby { get; set; }

    public IList<Claim> Claims { get; set; }

    public string SecurityStamp { get; set; }

    public string PasswordHash { get; set; }
}
//------------------Ʌ

//----------------------------V  UserStoreCore.cs
public partial class UserStore : IUserStore<AppUser>
{
    private ConcurrentDictionary<string, AppUser> users = new ConcurrentDictionary<string, AppUser>();

    public Task<IdentityResult> CreateAsync(AppUser user, CancellationToken token)
    {
        if (!users.ContainsKey(user.Id) && users.TryAdd(user.Id, user))
        {
            return Task.FromResult(IdentityResult.Success);
        }
        return Task.FromResult(Error);
    }

    public Task<IdentityResult> DeleteAsync(AppUser user, CancellationToken token)
    {
        if (users.ContainsKey(user.Id)
        && users.TryRemove(user.Id, out user))
        {
            return Task.FromResult(IdentityResult.Success);
        }
        return Task.FromResult(Error);
    }

    public Task<IdentityResult> UpdateAsync(AppUser user, CancellationToken token)
    {
        if (users.ContainsKey(user.Id))
        {
            users[user.Id].UpdateFrom(user);
            return Task.FromResult(IdentityResult.Success);
        }
        return Task.FromResult(Error);
    }

    public void Dispose()
    {
        // do nothing
    }

    private IdentityResult Error => IdentityResult.Failed(new IdentityError
    {
        Code = "StorageFailure",
        Description = "User Store Error"
    });
}
//----------------------------Ʌ

//----------------------------V  UserStore.cs
public partial class UserStore
{
    public ILookupNormalizer Normalizer { get; set; }
    
    public IPasswordHasher<AppUser> PasswordHasher { get; set; }

    public UserStore(ILookupNormalizer normalizer, IPasswordHasher<AppUser> passwordHasher) 
    { 
        Normalizer = normalizer; 
        PasswordHasher = passwordHasher;
        SeedStore();
    }

    private void SeedStore()
    {
        var customData = new Dictionary<string, (string food, string hobby)> {
            { "Alice", ("Pizza", "Running") },
            { "Bob", ("Ice Cream", "Cinema") },
            { "Charlie", ("Burgers", "Cooking") }
        };

        int idCounter = 0;
        string EmailFromName(string name) => $"{name.ToLower()}@example.com";

        foreach (string name in UsersAndClaims.Users)
        {
            AppUser user = new AppUser
            {
                Id = (++idCounter).ToString(),
                UserName = name,
                NormalizedUserName = Normalizer.NormalizeName(name),
                EmailAddress = EmailFromName(name),
                NormalizedEmailAddress = Normalizer.NormalizeEmail(EmailFromName(name)),
                EmailAddressConfirmed = true,
                PhoneNumber = "123-4567",
                PhoneNumberConfirmed = true,
                FavoriteFood = customData[name].food,
                Hobby = customData[name].hobby,
                SecurityStamp = "InitialStamp"
            };

            user.Claims = UsersAndClaims.UserData[user.UserName].Select(role => new Claim(ClaimTypes.Role, role)).ToList();  // only realted to Role claim
            user.PasswordHash = PasswordHasher.HashPassword(user, "MySecret1$");
            users.TryAdd(user.Id, user);
        }
    }
}
//----------------------------Ʌ

//----------------------------V  UserStoreNames.cs
public partial class UserStore
{
    public Task<string> GetNormalizedUserNameAsync(AppUser user, CancellationToken token)
    {
        return Task.FromResult(user.NormalizedUserName);
    }

    public Task<string> GetUserIdAsync(AppUser user, CancellationToken token)
    {
        return Task.FromResult(user.Id);
    }

    public Task<string> GetUserNameAsync(AppUser user, CancellationToken token)
    {
        return Task.FromResult(user.UserName);
    }

    public Task SetNormalizedUserNameAsync(AppUser user, string normalizedName, CancellationToken token)
    {
        return Task.FromResult(user.NormalizedUserName = normalizedName);
    }

    public Task SetUserNameAsync(AppUser user, string userName, CancellationToken token)
    {
        return Task.FromResult(user.UserName = userName);
    }
}
//----------------------------Ʌ

//----------------------------V  UserStoreQuery.cs
public partial class UserStore
{
    public Task<AppUser> FindByIdAsync(string userId, CancellationToken token)
    {
        return Task.FromResult(users.ContainsKey(userId) ? users[userId].Clone() : null);
    }

    public Task<AppUser> FindByNameAsync(string normalizedUserName, CancellationToken token)
    {
        return Task.FromResult(users.Values.FirstOrDefault(user => user.NormalizedUserName == normalizedUserName)?.Clone());
    }
}
//----------------------------Ʌ

//----------------------------V  UserStoreQueryable.cs
public partial class UserStore : IQueryableUserStore<AppUser>
{
    public IQueryable<AppUser> Users => users.Values.Select(user => user.Clone()).AsQueryable<AppUser>();
}
//----------------------------Ʌ

//----------------------------V  UserStoreEmail.cs
public partial class UserStore : IUserEmailStore<AppUser>
{
    public Task<AppUser> FindByEmailAsync(string normalizedEmail, CancellationToken token) => Task.FromResult(Users.FirstOrDefault(user => user.NormalizedEmailAddress == normalizedEmail));

    public Task<string> GetEmailAsync(AppUser user, CancellationToken token) => Task.FromResult(user.EmailAddress);

    public Task SetEmailAsync(AppUser user, string email, CancellationToken token)
    {
        user.EmailAddress = email;
        return Task.CompletedTask;
    }

    public Task<string> GetNormalizedEmailAsync(AppUser user, CancellationToken token) => Task.FromResult(user.NormalizedEmailAddress);

    public Task SetNormalizedEmailAsync(AppUser user, string normalizedEmail, CancellationToken token)
    {
        user.NormalizedEmailAddress = normalizedEmail;
        return Task.CompletedTask;
    }

    public Task<bool> GetEmailConfirmedAsync(AppUser user, CancellationToken token) => Task.FromResult(user.EmailAddressConfirmed);

    public Task SetEmailConfirmedAsync(AppUser user, bool confirmed, CancellationToken token)
    {
        user.EmailAddressConfirmed = confirmed;
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ

//----------------------------V
public partial class UserStore : IUserPhoneNumberStore<AppUser>
{
    public Task<string> GetPhoneNumberAsync(AppUser user, CancellationToken token) => Task.FromResult(user.PhoneNumber);

    public Task SetPhoneNumberAsync(AppUser user, string phoneNumber, CancellationToken token)
    {
        user.PhoneNumber = phoneNumber;
        return Task.CompletedTask;
    }

    public Task<bool> GetPhoneNumberConfirmedAsync(AppUser user, CancellationToken token) => Task.FromResult(user.PhoneNumberConfirmed);

    public Task SetPhoneNumberConfirmedAsync(AppUser user, bool confirmed, CancellationToken token)
    {
        user.PhoneNumberConfirmed = confirmed;
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ

//----------------------------V
public partial class UserStore : IUserClaimStore<AppUser>, IEqualityComparer<Claim>
{
    public Task AddClaimsAsync(AppUser user, IEnumerable<Claim> claims, CancellationToken token)
    {
        if (user.Claims == null)
        {
            user.Claims = new List<Claim>();
        }

        foreach (Claim claim in claims)
        {
            user.Claims.Add(claim);
        }

        return Task.CompletedTask;
    }

    public Task<IList<Claim>> GetClaimsAsync(AppUser user, CancellationToken token) => Task.FromResult(user.Claims);

    public Task RemoveClaimsAsync(AppUser user, IEnumerable<Claim> claims, CancellationToken token)
    {
        foreach (Claim c in user.Claims.Intersect(claims, this).ToList())
        {
            user.Claims.Remove(c);
        }

        return Task.CompletedTask;
    }

    public async Task ReplaceClaimAsync(AppUser user, Claim oldclaim, Claim newClaim, CancellationToken token)
    {
        await RemoveClaimsAsync(user, new[] { oldclaim }, token);
        user.Claims.Add(newClaim);
    }

    public Task<IList<AppUser>> GetUsersForClaimAsync(Claim claim, CancellationToken token)
    {
        return Task.FromResult(Users.Where(u => u.Claims.Any(c => Equals(c, claim))).ToList() as IList<AppUser>);
    }

    public bool Equals(Claim first, Claim second)
    {
        return first.Type == second.Type && string.Equals(first.Value, second.Value, StringComparison.OrdinalIgnoreCase);
    }

    public int GetHashCode(Claim claim) => claim.Type.GetHashCode() + claim.Value.GetHashCode();
}
//----------------------------Ʌ

//----------------------------V
public partial class UserStore : IUserRoleStore<AppUser>
{
    public Task<IList<AppUser>> GetUsersInRoleAsync(string roleName, CancellationToken token)
        => GetUsersForClaimAsync(new Claim(ClaimTypes.Role, roleName), token);

    public async Task<IList<string>> GetRolesAsync(AppUser user, CancellationToken token)
    {
        return (await GetClaimsAsync(user, token))
            .Where(claim => claim.Type == ClaimTypes.Role)
            .Distinct().Select(claim => Normalizer.NormalizeName(claim.Value))
            .ToList();
    }

    public async Task<bool> IsInRoleAsync(AppUser user, string normalizedRoleName, CancellationToken token)
    {
        return (await GetRolesAsync(user, token)).Any(role => Normalizer.NormalizeName(role) == normalizedRoleName);
    }

    public Task AddToRoleAsync(AppUser user, string roleName, CancellationToken token)
        => AddClaimsAsync(user, GetClaim(roleName), token);

    public async Task RemoveFromRoleAsync(AppUser user, string normalizedRoleName, CancellationToken token)
    {
        IEnumerable<Claim> claimsToDelete =
            (await GetClaimsAsync(user, token))
            .Where(claim => claim.Type == ClaimTypes.Role && Normalizer.NormalizeName(claim.Value) == normalizedRoleName);

        await RemoveClaimsAsync(user, claimsToDelete, token);
    }

    private IEnumerable<Claim> GetClaim(string role) => new[] { new Claim(ClaimTypes.Role, role) };
}
//----------------------------Ʌ

//----------------------------V
public partial class UserStore : IUserSecurityStampStore<AppUser>  // check UserManager source code's UpdateSecurityStampInternal
{
    public Task<string> GetSecurityStampAsync(AppUser user, CancellationToken token) => Task.FromResult(user.SecurityStamp);

    public Task SetSecurityStampAsync(AppUser user, string stamp, CancellationToken token)
    {
        user.SecurityStamp = stamp;
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ

//----------------------------V
public partial class UserStore : IUserPasswordStore<AppUser>
{
    public Task<string> GetPasswordHashAsync(AppUser user, CancellationToken token)
        => Task.FromResult(user.PasswordHash);

    public Task<bool> HasPasswordAsync(AppUser user, CancellationToken token)
        => Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

    public Task SetPasswordHashAsync(AppUser user, string passwordHash, CancellationToken token)
    {
        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ

//--------------------->>
public class Normalizer : ILookupNormalizer
{
    public string NormalizeName(string name) => name.Normalize().ToLowerInvariant();
    
    public string NormalizeEmail(string email) => email.Normalize().ToLowerInvariant();
}
//---------------------<<
```

```C#
//--------------------------------------V
public static class StoreClassExtentions  // allow change partial properties of the users when model binding involved, you get the idea
{
    public static T UpdateFrom<T>(this T target, T source)
    {
        UpdateFrom(target, source, out bool discardValue);
        return target;
    }

    public static T UpdateFrom<T>(this T target, T source, out bool changes)
    {
        object value;
        int changeCount = 0;
        Type classType = typeof(T);
        foreach (var prop in classType.GetProperties())
        {
            if (prop.PropertyType.IsGenericType && prop.PropertyType.GetGenericTypeDefinition().Equals(typeof(IList<>)))
            {
                Type listType = typeof(List<>).MakeGenericType(prop.PropertyType
                .GetGenericArguments()[0]);
                IList sourceList = prop.GetValue(source) as IList;
                if (sourceList != null)
                {
                    prop.SetValue(target, Activator.CreateInstance(listType,
                    sourceList));
                }
            }
            else
            {
                if ((value = prop.GetValue(source)) != null
                && !value.Equals(prop.GetValue(target)))
                {
                    classType.GetProperty(prop.Name).SetValue(target, value);
                    changeCount++;
                }
            }
        }
        changes = changeCount > 0;
        return target;
    }

    public static T Clone<T>(this T original) => Activator.CreateInstance<T>().UpdateFrom(original);
}
//--------------------------------------Ʌ

//-------------------------V
public class EmailValidator : IUserValidator<AppUser>
{
    private static string[] AllowedDomains = new[] { "example.com", "acme.com" };

    private static IdentityError err = new IdentityError { Description = "Email address domain not allowed" };

    public EmailValidator(ILookupNormalizer normalizer)
    {
        Normalizer = normalizer;
    }

    private ILookupNormalizer Normalizer { get; set; }

    public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
    {
        string normalizedEmail = Normalizer.NormalizeEmail(user.EmailAddress);

        if (AllowedDomains.Any(domain => normalizedEmail.EndsWith($"@{domain}")))
        {
            return Task.FromResult(IdentityResult.Success);
        }

        return Task.FromResult(IdentityResult.Failed(err));
    }
}
//-------------------------Ʌ
```


Usage from some Razor Pages:

```C#
//---------------------V
public class UsersModel : PageModel
{
    public UsersModel(UserManager<AppUser> userMgr)
    {
        UserManager = userMgr;
    }

    public UserManager<AppUser> UserManager { get; set; }

    public AppUser AppUserObject { get; set; } = new AppUser();

    public async Task OnGetAsync(string id)
    {
        if (id != null)
        {
            AppUserObject = await UserManager.FindByIdAsync(id) ?? new AppUser();
        }
    }

    public async Task<IActionResult> OnPost(AppUser user)
    {
        IdentityResult result;
        AppUser storeUser = await UserManager.FindByIdAsync(user.Id);
        if (storeUser == null)
        {
            result = await UserManager.CreateAsync(user);
        }
        else
        {
            storeUser.UpdateFrom(user);   // <-------------------perserve some properties then apply changes via UserManager.UpdateAsync
                                          // but the author didn't consider changes still apply if validation fails
            result = await UserManager.UpdateAsync(storeUser);  // <----------------apply built-in features such as validations then call UserStore.UpdateAsync
                                                                // so UserManager is like a wrapper
        }
        if (result.Succeeded)
        {
            return RedirectToPage("user", new { searchname = user.Id });
        }
        else
        {
            foreach (IdentityError err in result.Errors)
            {
                ModelState.AddModelError("", err.Description ?? "Error");
            }
            AppUserObject = user;
            return Page();
        }
    }
}
//---------------------Ʌ

//------------------------V
public class FindUserModel : PageModel
{
    public FindUserModel(UserManager<AppUser> userMgr)
    {
        UserManager = userMgr;
    }

    public UserManager<AppUser> UserManager { get; set; }

    public IEnumerable<AppUser> Users { get; set; } = Enumerable.Empty<AppUser>();

    [BindProperty(SupportsGet = true)]
    public string Searchname { get; set; }

    public async Task OnGet()
    {
        if (UserManager.SupportsQueryableUsers)
        {
            string normalizedName = UserManager.NormalizeName(Searchname ?? string.Empty);

            Users = string.IsNullOrEmpty(Searchname) ?
                UserManager.Users.OrderBy(u => u.UserName) :
                UserManager.Users.Where
                (
                    user => user.Id == Searchname || user.NormalizedUserName.Contains(normalizedName)
                ).OrderBy(u => u.UserName);

        }

        if (Searchname != null)
        {
            AppUser nameUser = await UserManager.FindByNameAsync(Searchname);
            if (nameUser != null)
            {
                Users = Users.Append(nameUser);
            }
            AppUser idUser = await UserManager.FindByIdAsync(Searchname);
            if (idUser != null)
            {
                Users = Users.Append(idUser);
            }
        }
    }

    public async Task<IActionResult> OnPostDelete(string id)
    {
        AppUser user = await UserManager.FindByIdAsync(id);
        if (user != null)
        {
            await UserManager.DeleteAsync(user);
        }

        return RedirectToPage();
    }
}
//------------------------Ʌ
```

===========================================================================

`IUserTwoFactorTokenProvider` related

```C#
public abstract class SimpleTokenGenerator : IUserTwoFactorTokenProvider<AppUser>
{
    protected virtual int CodeLength { get; } = 6;

    public virtual Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user)
    {
        return Task.FromResult(manager.SupportsUserSecurityStamp);
    }

    public virtual Task<string> GenerateAsync(string purpose, UserManager<AppUser> manager, AppUser user)
        => Task.FromResult(GenerateCode(purpose, user));

    public virtual Task<bool> ValidateAsync(string purpose, string token, UserManager<AppUser> manager, AppUser user)
        => Task.FromResult(GenerateCode(purpose, user).Equals(token));

    protected virtual string GenerateCode(string purpose, AppUser user)  // purpose contains "ChangeEmail:" or "ChangePhoneNumber:" prefix plus new value of email/number
    {                                                                    // such as "ChangeEmail:newEmailAddress" or "ChangePhoneNumber:newNumber"
        HMACSHA1 hashAlgorithm = new HMACSHA1(Encoding.UTF8.GetBytes(user.SecurityStamp));

        byte[] hashCode = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(GetData(purpose, user)));

        string token = BitConverter.ToString(hashCode[^CodeLength..]).Replace("-", "");  // token is associated to purpose and user.SecurityStamp only
                                                                                         // doesn't associated with user's other properties
        return token;
    }

    protected virtual string GetData(string purpose, AppUser user) => $"{purpose}{user.SecurityStamp}";
}

public class EmailConfirmationTokenGenerator : SimpleTokenGenerator
{
    protected override int CodeLength => 12;
    public async override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user)
    {
        return await base.CanGenerateTwoFactorTokenAsync(manager, user) && !string.IsNullOrEmpty(user.EmailAddress) && !user.EmailAddressConfirmed; 
    }
}

```C#
//--------------------------------V
public class EmailPhoneChangeModel : PageModel
{
    public EmailPhoneChangeModel(UserManager<AppUser> manager, IEmailSender email, ISMSSender sms)
    {
        UserManager = manager;
        EmailSender = email;
        SMSSender = sms;
    }
    public UserManager<AppUser> UserManager { get; set; }

    public AppUser AppUser { get; set; }

    public IEmailSender EmailSender { get; set; }

    public ISMSSender SMSSender { get; set; }

    [BindProperty(SupportsGet = true)]
    public string DataType { get; set; }

    public bool IsEmail => DataType.Equals("email");

    public string LabelText => DataType == "email" ? "Email Address" : "Phone Number";
    public string CurrentValue => IsEmail ? AppUser.EmailAddress : AppUser.PhoneNumber;

    public async Task OnGetAsync(string id)
    {
        AppUser = await UserManager.FindByIdAsync(id);
    }

    public async Task<IActionResult> OnPost(string id, string dataValue)  // dataValue is the new email address or phone number
    {
        AppUser = await UserManager.FindByIdAsync(id);

        if (IsEmail)
        {
            // GenerateChangeEmailTokenAsync eventually calls user-define IUserTwoFactorTokenProvider.GenerateAsync()
            string token = await UserManager.GenerateChangeEmailTokenAsync(AppUser, dataValue);

            EmailSender.SendMessage(AppUser, "Confirm Email", "Click the link to confirm your email address:", $"http://localhost:5000/validate/{id}/email/{dataValue}:{token}");
        }
        else
        {
            string token = await UserManager.GenerateChangePhoneNumberTokenAsync(AppUser, dataValue);
            SMSSender.SendMessage(AppUser, $"Your confirmation token is {token}");
        }

        return RedirectToPage("EmailPhoneConfirmation", new { id, dataType = DataType, dataValue });
    }
}
//--------------------------------Ʌ

//--------------------------------------V
public class EmailPhoneConfirmationModel : PageModel
{
    public EmailPhoneConfirmationModel(UserManager<AppUser> manager) => UserManager = manager;

    public UserManager<AppUser> UserManager { get; set; }

    [BindProperty(SupportsGet = true)]
    public string DataType { get; set; }

    [BindProperty(SupportsGet = true)]
    public string DataValue { get; set; }

    public bool IsEmail => DataType.Equals("email");

    public AppUser AppUser { get; set; }

    public async Task<IActionResult> OnGetAsync(string id)
    {
        // ...
    }

    // dataValue is new email/phone value that is from UI's <input type="hidden" name="dataValue" value="@Model.DataValue" />
    public async Task<IActionResult> OnPostAsync(string id, string token, string dataValue)  
    {
        AppUser = await UserManager.FindByIdAsync(id);
        return await Validate(dataValue, token);
    }

    private async Task<IActionResult> Validate(string value, string token)  // value is the new email/phone
    {
        IdentityResult result;

        if (IsEmail)
        {
            // calling method "ChangeEmailAsync" seems like anti-pattern, as you would like to check if the new email can be changed as something like
            // if (UserManager.CanChangeEmailAsync(AppUser, value, token)), but ChangeEmailAsync internally calls VerifyUserTokenAsync check t4 source code
            result = await UserManager.ChangeEmailAsync(AppUser, value, token);                       
        }
        else
        {
            result = await UserManager.ChangePhoneNumberAsync(AppUser, value, token);
        }

        if (result.Succeeded)
        {
            return Redirect($"/users/edit/{AppUser.Id}");
        }
        else
        {
            foreach (IdentityError err in result.Errors)
            {
                ModelState.AddModelError(string.Empty, err.Description);
            }
            return Page();
        }
    }
}
//--------------------------------------Ʌ
```

```C#
// Old Approach-you have to create Claims, ClaimsIdentity and ClaimsPrincipal on your own
//----------------------V
public class SignInModel : PageModel
{
    // ...

    public async Task<ActionResult> OnPost(string username, [FromQuery] string returnUrl)
    {
        Claim claim = new Claim(ClaimTypes.Name, username);
        ClaimsIdentity ident = new ClaimsIdentity("simpleform");
        ident.AddClaim(claim);

        // calling HttpContext.SignInAsync invokes authenticate handler such as CookieAuthenticationHandler.HandleSignInAsync() mehotd
        await HttpContext.SignInAsync(new ClaimsPrincipal(ident));   // <---------CookieAuthenticationHandler derilizes the identity/claims into cookies    
                                                                     // to be precisely, serilizes AuthenticationTicket(contains ClaimsPrincipal) into cookies
        return Redirect(returnUrl ?? "/signin");
    }
}
//----------------------Ʌ
```

```C#
// New Approach-Use SignInManager
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        // ...   
        services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>, AppUserClaimsPrincipalFactory>(); 

        services.AddIdentityCore<AppUser>(opts => 
        {  
           // ...
        })
        .AddSignInManager(); 
      
    }
}
//------------------Ʌ

//----------------------V
public class SignInModel : PageModel
{
    public SignInModel(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)  // <-------------------------DI
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

        await SignInManager.SignInAsync(user, false);   // <-------------------SignInManager.SignInAsync calls IUserClaimsPrincipalFactory.CreateAsync internally
                                                        // then it eventually calls HttpContext.SignInAsync(new ClaimsPrincipal(...))
        return Redirect(returnUrl ?? "/signin");
    }

    public async Task<ActionResult> OnPost(string username, string password, [FromQuery] string returnUrl)  // with password
    {
        SignInResult result = SignInResult.Failed;
        AppUser user = await UserManager.FindByEmailAsync(username);

        if (user != null && !string.IsNullOrEmpty(password))
        {
            result = await SignInManager.PasswordSignInAsync(user, password, false, true);
        }
        if (!result.Succeeded)
        {
            Code = StatusCodes.Status401Unauthorized;
            return Page();
        }
        return Redirect(returnUrl ?? "/signin");
    }

    public async Task<ActionResult> OnPostBeforeUsingHttpContextSignInAsync(string username, [FromQuery] string returnUrl)
    {
        Claim claim = new Claim(ClaimTypes.Name, username);
        ClaimsIdentity ident = new ClaimsIdentity("simpleform");
        ident.AddClaim(claim);

        // have to manually setup ClaimsIdentity and ClaimsPrincipal as HttpContext.SignInAsync() takes ClaimsPrincipal
        // while SignInManager.SignInAsync() takes TUser
        await HttpContext.SignInAsync(new ClaimsPrincipal(ident));               
    } 
}
//----------------------Ʌ

//----------------------------------------V
public class AppUserClaimsPrincipalFactory : IUserClaimsPrincipalFactory<AppUser>  // convert AppUser to ClaimsPrincipal that contains claims based on AppUser's properties
{
    public Task<ClaimsPrincipal> CreateAsync(AppUser user)
    {
        ClaimsIdentity identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);

        identity.AddClaims(new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.EmailAddress)
            });

        if (!string.IsNullOrEmpty(user.Hobby))
        {
            identity.AddClaim(new Claim("Hobby", user.Hobby));
        }
        if (!string.IsNullOrEmpty(user.FavoriteFood))
        {
            identity.AddClaim(new Claim("FavoriteFood", user.FavoriteFood));
        }
        if (user.Claims != null)
        {
            identity.AddClaims(user.Claims);  // <-------------add Roles
        }

        return Task.FromResult(new ClaimsPrincipal(identity));
    }
}
//----------------------------------------Ʌ
```

```C#
//------------------------------V this is for users still remember their password but want to change passwords
public class PasswordChangeModel : PageModel
{
    public PasswordChangeModel(UserManager<AppUser> manager) => UserManager = manager;
    public UserManager<AppUser> UserManager { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool Success { get; set; } = false;

    public async Task<IActionResult> OnPost(string oldPassword, string newPassword)
    {
        string username = HttpContext.User.Identity.Name;

        if (username != null)
        {
            AppUser user = await UserManager.FindByNameAsync(username);
            if (user != null && !string.IsNullOrEmpty(oldPassword) && !string.IsNullOrEmpty(newPassword))
            {
                IdentityResult result = 
                    await UserManager.ChangePasswordAsync(user, oldPassword, newPassword);  // <---------------- check oldPasswword in IUserPasswordStore

                if (result.Succeeded)
                    Success = true;
                }
                else{
                    foreach (IdentityError err in result.Errors)
                        ModelState.AddModelError("", err.Description);
                }
            }
        }
        return Page();
    }
}
//------------------------------Ʌ

//-----------------------------VV this is for users who doesn't remember their passwords
public class PasswordResetModel : PageModel
{
    public PasswordResetModel(UserManager<AppUser> manager, ISMSSender sender)
    {
        UserManager = manager;
        SMSSender = sender;
    }

    public UserManager<AppUser> UserManager { get; set; }

    public ISMSSender SMSSender { get; set; }

    public async Task<IActionResult> OnPost(string email)
    {
        AppUser user = await UserManager.FindByEmailAsync(email);
        if (user != null)
        {
            string token = await UserManager.GeneratePasswordResetTokenAsync(user);  // <--------------internally calls IUserTwoFactorTokenProvider.GenerateAsync()
            SMSSender.SendMessage(user, $"Your password reset token is {token}");
        }
        return RedirectToPage("PasswordResetConfirm", new { email });
    }
}

public class PasswordResetConfirmModel : PageModel
{
    public PasswordResetConfirmModel(UserManager<AppUser> manager) => UserManager = manager;
    public UserManager<AppUser> UserManager { get; set; }

    // ...

    public async Task<IActionResult> OnPostAsync(string password, string token)
    {
        AppUser user = await UserManager.FindByEmailAsync(Email);

        if (user != null)
        {
            IdentityResult result = await UserManager.ResetPasswordAsync(user, token, password);  // <-------------internally calls IUserTwoFactorTokenProvider.ValidateAsync()
            if (result.Succeeded) {
                return RedirectToPage(new { Changed = true });
            }
            else {
                foreach (IdentityError err in result.Errors) {
                    ModelState.AddModelError("", err.Description);
                }
            }
        }
        else {
            ModelState.AddModelError("", "Password Change Error");
        }
        return Page();
    }
}
//-----------------------------ɅɅ
```

## Setting Passwords Administratively

Administrative password resets require a different approach because the administrator doesn’t know the user's password and there is no method for changing a password without either the existing password or a confirmation code. The most reliable way to let an administrator change a password is to remove the existing password and add a new one

```C#
//---------------------V
public class UsersModel : PageModel
{
    public UsersModel(UserManager<AppUser> userMgr) => UserManager = userMgr;
    public UserManager<AppUser> UserManager { get; set; }
    // ...
    public async Task OnGetAsync(string id)
    {
        // ...
    }

    public async Task<IActionResult> OnPost(AppUser user, string newPassword)
    {
        IdentityResult result = IdentityResult.Success;
        AppUser storeUser = await UserManager.FindByIdAsync(user.Id);
        if (storeUser == null) {
            // ...
            result = await UserManager.CreateAsync(user, newPassword);
        }
        else {
            storeUser.UpdateFrom(user, out bool changed);

            if (newPassword != null) {
                if (await UserManager.HasPasswordAsync(storeUser))  // <--------------------------
                {
                    await UserManager.RemovePasswordAsync(storeUser);  // <--------------------------
                }
                result = await UserManager.AddPasswordAsync(storeUser, newPassword);  // <--------------------------
            }

            if (changed && UserManager.SupportsUserSecurityStamp)  {
                await UserManager.UpdateSecurityStampAsync(storeUser);
            }

            // ...
        }
        // ...
    }
}
//---------------------Ʌ
```


## Role Store ---------------------------------------------------------------------------------V 

```C#
//------------------V
public class AppRole
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; }
    public string NormalizedName { get; set; }
    public IList<Claim> Claims { get; set; }
}
//------------------Ʌ

//----------------------------V
public partial class RoleStore
{
    public ILookupNormalizer Normalizer { get; set; }

    public RoleStore(ILookupNormalizer normalizer)
    {
        Normalizer = normalizer;
        SeedStore();
    }

    private void SeedStore()
    {
        var roleData = new List<string> { "Administrator", "User", "Sales", "Support" };

        var claims = new Dictionary<string, IEnumerable<Claim>> {
                { "Administrator", new [] { new Claim("AccessUserData", "true"), new Claim(ClaimTypes.Role, "Support") } },
                { "Support", new [] { new Claim(ClaimTypes.Role, "User" )} }
            };

        int idCounter = 0;
        foreach (string roleName in roleData)
        {
            AppRole role = new AppRole
            {
                Id = (++idCounter).ToString(),
                Name = roleName,
                NormalizedName = Normalizer.NormalizeName(roleName)
            };

            if (claims.ContainsKey(roleName))
            {
                role.Claims = claims[roleName].ToList<Claim>();
            }

            roles.TryAdd(role.Id, role);
        }
    }
}
//----------------------------Ʌ

//----------------------------V
public partial class RoleStore : IRoleStore<AppRole>
{
    private ConcurrentDictionary<string, AppRole> roles = new ConcurrentDictionary<string, AppRole>();

    // CRUD related
    public Task<IdentityResult> CreateAsync(AppRole role, CancellationToken token)
    {
        if (!roles.ContainsKey(role.Id) && roles.TryAdd(role.Id, role))
        {
            return Task.FromResult(IdentityResult.Success);
        }
        return Task.FromResult(Error);
    }

    public Task<IdentityResult> DeleteAsync(AppRole role, CancellationToken token)
    {
        if (roles.ContainsKey(role.Id) && roles.TryRemove(role.Id, out role))
        {
            return Task.FromResult(IdentityResult.Success);
        }
        return Task.FromResult(Error);
    }

    public Task<IdentityResult> UpdateAsync(AppRole role, CancellationToken token)
    {
        if (roles.ContainsKey(role.Id))
        {
            roles[role.Id].UpdateFrom(role);
            return Task.FromResult(IdentityResult.Success);
        }
        return Task.FromResult(Error);
    }
    //

    // Role Name related
    public Task<string> GetRoleIdAsync(AppRole role, CancellationToken token) 
        => Task.FromResult(role.Id);

    public Task<string> GetRoleNameAsync(AppRole role, CancellationToken token)
        => Task.FromResult(role.Name);

    public Task SetRoleNameAsync(AppRole role, string roleName, CancellationToken token)
    {
        role.Name = roleName;
        return Task.CompletedTask;
    }

    public Task<string> GetNormalizedRoleNameAsync(AppRole role, CancellationToken token) 
        => Task.FromResult(role.NormalizedName);

    public Task SetNormalizedRoleNameAsync(AppRole role, string normalizedName, CancellationToken token)
    {
        role.NormalizedName = normalizedName;
        return Task.CompletedTask;
    }
    //

    public void Dispose()
    {
        // do nothing
    }

    private IdentityResult Error => IdentityResult.Failed(new IdentityError
    {
        Code = "StorageFailure",
        Description = "Role Store Error"
    });
}
//----------------------------Ʌ

//----------------------------V
public partial class RoleStore : IQueryableRoleStore<AppRole>
{
    public Task<AppRole> FindByIdAsync(string id, CancellationToken token)
        => Task.FromResult(roles.ContainsKey(id) ? roles[id].Clone() : null);

    public Task<AppRole> FindByNameAsync(string name, CancellationToken token)
        => Task.FromResult(roles.Values.FirstOrDefault(r => r.NormalizedName == name)?.Clone());

    public IQueryable<AppRole> Roles => roles.Values.Select(role => role.Clone()).AsQueryable<AppRole>();
}
//----------------------------Ʌ

//----------------------------V
public partial class RoleStore : IRoleClaimStore<AppRole>
{
    public Task AddClaimAsync(AppRole role, Claim claim, CancellationToken token = default)
    {
        role.Claims.Add(claim);
        return Task.CompletedTask;
    }

    public Task<IList<Claim>> GetClaimsAsync(AppRole role, CancellationToken token = default)
        => Task.FromResult(role.Claims ?? new List<Claim>());

    public Task RemoveClaimAsync(AppRole role, Claim claim, CancellationToken token = default)
    {
        role.Claims = role.Claims.Where(c => !(string.Equals(c.Type, claim.Type) && string.Equals(c.Value, claim.Value))).ToList<Claim>();
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ

//----------------------------------------V
public class AppUserClaimsPrincipalFactory : IUserClaimsPrincipalFactory<AppUser>  // need to be registered as Scoped instead of Singleton now because the dependency
{                                                                                  // userManager and roleManager are scoped   
    public AppUserClaimsPrincipalFactory(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager)
    {
        UserManager = userManager;
        RoleManager = roleManager;
    }

    public UserManager<AppUser> UserManager { get; set; }
    public RoleManager<AppRole> RoleManager { get; set; }

    public async Task<ClaimsPrincipal> CreateAsync(AppUser user)
    {
        ClaimsIdentity identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);

        identity.AddClaims(new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.EmailAddress)
            });

        if (!string.IsNullOrEmpty(user.Hobby))
        {
            identity.AddClaim(new Claim("Hobby", user.Hobby));
        }
        if (!string.IsNullOrEmpty(user.FavoriteFood))
        {
            identity.AddClaim(new Claim("FavoriteFood", user.FavoriteFood));
        }
        if (user.Claims != null)
        {
            identity.AddClaims(user.Claims);
        }

        if (UserManager.SupportsUserRole && RoleManager.SupportsRoleClaims)  // <------------------------
        {
            foreach (string roleName in await UserManager.GetRolesAsync(user))
            {
                AppRole role = await RoleManager.FindByNameAsync(roleName);
                if (role != null)
                {
                    identity.AddClaims(await RoleManager.GetClaimsAsync(role));
                }
            }
        }

        return new ClaimsPrincipal(identity);
    }
}
//----------------------------------------Ʌ
```

## Role Store End -------------------------------------------------------------------Ʌ


## Lockouts and Two-Factor Sign-Ins--------------------------------------------------V

```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        // ...
        services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();

        services.AddIdentityCore<AppUser>(opts => // opts is IdentityOptions
        {
            // ...
            opts.Lockout.MaxFailedAccessAttempts = 3;  // default is 5 attempts
            opts.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);  // default is 5 mins
        })
        .AddTokenProvider<TwoFactorSignInTokenGenerator>(IdentityConstants.TwoFactorUserIdScheme)
        ...

        services.AddAuthentication(opts => {  // opts is AuthenticationOptions
            opts.DefaultScheme = IdentityConstants.ApplicationScheme;
        })
        .AddCookie(IdentityConstants.ApplicationScheme, opts => {
            opts.LoginPath = "/signin";
            opts.AccessDeniedPath = "/signin/403";
        })
        .AddCookie(IdentityConstants.TwoFactorUserIdScheme)       // <-------------------------add each scheme 
        .AddCookie(IdentityConstants.TwoFactorRememberMeScheme);  // <-------------------------
        // ...
    }
}
//------------------Ʌ

//------------------V
public class AppUser
{
    // ...
    public bool CanUserBeLockedout { get; set; } = true;
    public int FailedSigninCount { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public bool TwoFactorEnabled { get; set; }
}
//------------------Ʌ

//---------------------------V restricting SignIn to Confirmed Accounts
public class UserConfirmation : IUserConfirmation<AppUser> // <-----------------used in SignInManager's PreSignInCheck -> CanSignInAsync, check c1 and c2
{                                                         
    public async Task<bool> IsConfirmedAsync(UserManager<AppUser> manager, AppUser user)
    {
        return await manager
            .IsInRoleAsync(user, "Administrator") || (await manager.GetClaimsAsync(user))
            .Any(claim => claim.Type == "UserConfirmed" &&
            string.Compare(claim.Value, "true", true) == 0);
    }
}
//---------------------------Ʌ

//----------------------------V
public partial class UserStore : IUserLockoutStore<AppUser>
{
    public Task SetLockoutEnabledAsync(AppUser user, bool enabled, CancellationToken token)
    {
        user.CanUserBeLockedout = enabled;
        return Task.CompletedTask;
    }

    public Task<bool> GetLockoutEnabledAsync(AppUser user, CancellationToken token)
        => Task.FromResult(user.CanUserBeLockedout);

    public Task<int> GetAccessFailedCountAsync(AppUser user, CancellationToken token)
        => Task.FromResult(user.FailedSignInCount);

    public Task<int> IncrementAccessFailedCountAsync(AppUser user, CancellationToken token)
        => Task.FromResult(++user.FailedSignInCount);

    public Task ResetAccessFailedCountAsync(AppUser user, CancellationToken token)
    {
        user.FailedSignInCount = 0;
        return Task.CompletedTask;
    }

    public Task SetLockoutEndDateAsync(AppUser user, DateTimeOffset? lockoutEnd, CancellationToken token)
    {
        user.LockoutEnd = lockoutEnd;
        return Task.CompletedTask;
    }

    public Task<DateTimeOffset?> GetLockoutEndDateAsync(AppUser user, CancellationToken token)
        => Task.FromResult(user.LockoutEnd);
}
//----------------------------Ʌ

//----------------------------V
public partial class UserStore : IUserTwoFactorStore<AppUser>
{
    public Task<bool> GetTwoFactorEnabledAsync(AppUser user, CancellationToken token)
        => Task.FromResult(user.TwoFactorEnabled);

    public Task SetTwoFactorEnabledAsync(AppUser user, bool enabled, CancellationToken token)
    {
        user.TwoFactorEnabled = enabled;
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ

//----------------------------------------V
public class TwoFactorSignInTokenGenerator : SimpleTokenGenerator
{
    protected override int CodeLength => 3;
    public override Task<bool> CanGenerateTwoFactorTokenAsync(
    UserManager<AppUser> manager, AppUser user)
    {
        return Task.FromResult(user.TwoFactorEnabled);
    }
}
//----------------------------------------Ʌ

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

    public string Message { get; set; }
    // ...

    public async Task<ActionResult> OnPost(string username, string password, [FromQuery] string returnUrl)
    {
        SignInResult result = SignInResult.Failed;
        AppUser user = await UserManager.FindByEmailAsync(username);

        if (user != null && !string.IsNullOrEmpty(password))
        {
            result = await SignInManager.PasswordSignInAsync(user, password, false, true);  // if pass true as the last argument (lockoutOnFailure) then lockout is disabled
            /*                                                                                         
               SignInManager.PasswordSignInAsync can generate one of kind of specific cookie by making one of the call which depends on IsTwoFactorEnabledAsync(user):

               A. Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId, loginProvider));

                  StoreTwoFactorInfo generates a limited subsut of claims which only contains:
                      new Claim(ClaimTypes.Name, userId) and optional new Claim(ClaimTypes.AuthenticationMethod, loginProvider)
                                                                           
               B. Context.SignInAsync(AuthenticationScheme, ...)  where AuthenticationScheme is IdentityConstants.ApplicationScheme (i.e "Identity.Application")
                
                  this is when  a normal non-mfa SignIns like SignInWithClaimsAsync gererated full claimsa

                if IsTwoFactorEnabledAsync(user) is true, the request goes path A, result is `SignInResult.TwoFactorRequired` 
            */
        }
        if (!result.Succeeded)
        {
            //--------------------------------------------------------------------V <-------------------------------------------
            if (result.IsLockedOut)
            {
                TimeSpan remaining = (await UserManager.GetLockoutEndDateAsync(user)).GetValueOrDefault().Subtract(DateTimeOffset.Now);
                Message = $"Locked Out for {remaining.Minutes} mins and" + $" {remaining.Seconds} secs";
            }
            else if (result.RequiresTwoFactor) 
            {
                return RedirectToPage("/SignInTwoFactor", new { returnUrl = returnUrl });
            }
            else if (result.IsNotAllowed)  // <------------------------------------------------c2
            {
                Message = "Sign In Not Allowed";
            }
            //--------------------------------------------------------------------Ʌ
            else
            {
                Message = "Access Denied";
            }
            return Page();
        }
        return Redirect(returnUrl ?? "/signin");
    }

    public async Task<ActionResult> OnPostBeforeUsingHttpContextSignInAsync(string username, [FromQuery] string returnUrl)
    {
        Claim claim = new Claim(ClaimTypes.Name, username);
        ClaimsIdentity ident = new ClaimsIdentity("simpleform");
        ident.AddClaim(claim);

        // calling HttpContext.SignInAsync invokes CookieAuthenticationHandler.HandleSignInAsync() mehotd
        await HttpContext.SignInAsync(new ClaimsPrincipal(ident));   // <---------CookieAuthenticationHandler deserilizes the identity/claims into cookies    
                                                                     // to be precisely, deserilizes AuthenticationTicket that contains ClaimsPrincipal
        return Redirect(returnUrl ?? "/signin");
    }
}
//----------------------Ʌ

//-------------------------------V Token Input Razor Page
public class SignInTwoFactorModel : PageModel
{
    public SignInTwoFactorModel(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, ISMSSender sender)
    {
        UserManager = userManager;
        SignInManager = signInManager;
        SMSSender = sender;
    }

    public UserManager<AppUser> UserManager { get; set; }
    public SignInManager<AppUser> SignInManager { get; set; }
    public ISMSSender SMSSender { get; set; }

    public async Task OnGet()
    {
        AppUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync(); // <----------it uses userId cookie generate by PasswordSignInAsyncpath's Path A
                                                                                  // calls Context.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme) interally 
                                                                                  // so CookieAuthenticationHandler read cookies then genereate AuthenticateResult that
                                                                                  // contains the ticket which can be queriy against UserManager.FindByIdAsync(userId)
        if (user != null)
        {
            await UserManager.UpdateSecurityStampAsync(user);

            string token = await UserManager.GenerateTwoFactorTokenAsync(user, IdentityConstants.TwoFactorUserIdScheme);

            SMSSender.SendMessage(user, $"Your security code is {token}");
        }
    }

    public async Task<IActionResult> OnPost(string smscode, string rememberMe, [FromQuery] string returnUrl)
    {
        AppUser user =
            await SignInManager.GetTwoFactorAuthenticationUserAsync();  // this is not actually needed as SignInManager.TwoFactorSignInAsync does it too

        if (user != null)
        {
            SignInResult result = await SignInManager.TwoFactorSignInAsync(IdentityConstants.TwoFactorUserIdScheme, smscode, true, !string.IsNullOrEmpty(rememberMe));
            /*
            SignInManager.TwoFactorSignInAsync does:
            1. calls Context.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme) first get Appuser first
            2. calls UserManager.VerifyTwoFactorTokenAsync(user, ...) 
            3. if step 2 passes, then does the following:
               1. if rememberClient, calls `Context.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme, principal, ...)` which 
                  create a TwoFactorRememberMeScheme cookie contains mainly userId as a claim
               2. calls Context.SignInAsync(AuthenticationScheme, ...)  where AuthenticationScheme is IdentityConstants.ApplicationScheme (i.e "Identity.Application")
                  this is a normal non-mfa SignIns that gererated full claims based on Appuser
            */
     
            if (result.Succeeded)
            {
                return Redirect(returnUrl ?? "/");
            }
            else if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "Locked out");
            }
            else if (result.IsNotAllowed)
            {
                ModelState.AddModelError("", "Not allowed");
            }
            else
            {
                ModelState.AddModelError("", "Authentication failed");
            }
        }

        return Page();
    }
}
//-------------------------------Ʌ

//-----------------------V
public class SignOutModel : PageModel
{
    public SignOutModel(SignInManager<AppUser> manager)
        => SignInManager = manager;

    public SignInManager<AppUser> SignInManager { get; set; }
    public string Username { get; set; }

    public void OnGet()
    {
        Username = User.Identity.Name ?? "(No Signed In User)";
    }

    public async Task<ActionResult> OnPost(string forgetMe)
    {
        if (!string.IsNullOrEmpty(forgetMe))
        {
            await SignInManager.ForgetTwoFactorClientAsync();  // calls Context.SignOutAsync(IdentityConstants.TwoFactorRememberMeScheme)
                                                               // to clear the relevent cookie
        }

        await HttpContext.SignOutAsync();  // <----------clear remaining fullset AppUser related cookies
        /*
        we can use SignInManager.SignOutAsync() here too, but it clears other cookies such as IdentityConstants.ExternalScheme and IdentityConstants.TwoFactorUserIdScheme cookies,
        and it will throw an exception for no handler for the external scheme if it is not being used properly
        */

        return RedirectToPage("SignIn");
    }
}
//-----------------------Ʌ
```

The "remember me" on the "second" SignIn page (`SignInTwoFactor` Razor Page) that prompt user to enter token and "forget me" in SignOut Razor Page works like this:

* After a user enter username and password and invoke `SignInManager.PasswordSignInAsync(...)`
  1. `TwoFactorUserIdScheme` cookie is generate by calling `Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId, ...));`
  `StoreTwoFactorInfo` generates a limited claims which only contains: `new Claim(ClaimTypes.Name, userId)` and optional `new Claim(ClaimTypes.AuthenticationMethod, ...)`
  (This `TwoFactorUserIdScheme` cookie will be read in `SignInTwoFactor` page) then user is redirectd to `SignInTwoFactor` page

  2. On `SignInTwoFactor` page, user enter the token and make a choice on "remember me" then invoke the call of
  `SignInManager.TwoFactorSignInAsync(IdentityConstants.TwoFactorUserIdScheme, smscode, true, !string.IsNullOrEmpty(rememberMe))`
  Inside the call,  `TwoFactorUserIdScheme` cookie is ready first, then invoke `Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme)` to clear `TwoFactorUserIdScheme` cookie. Then step a or b is picked:

    a. ("remember me" is ticked) 
       calls `Context.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme, principal, ...)` which  create a TwoFactorRememberMeScheme cookie contains mainly userId as a claim
    b. ("remember me" is not ticked)
       no TwoFactorRememberMeScheme cookie created
  
    then calls `Context.SignInAsync(AuthenticationScheme, ...)`  where AuthenticationScheme is IdentityConstants.ApplicationScheme (i.e "Identity.Application"), this is a normal non-mfa SignIns that gererated full claims based on `Appuser` (`IUserClaimsPrincipalFactory` involved too)

* User signout on the Signout page and make a choice on "forget me"

  c. ("forget me" is ticked) 
     invoke `SignInManager.ForgetTwoFactorClientAsync()` which calls `Context.SignOutAsync(IdentityConstants.TwoFactorRememberMeScheme)` to clear the relevent cookie
  
  d. ("forget me" is not ticked)
     nothing happen

  When user click SignOut button, `HttpContext.SignOutAsync()` is invoked to clear the main "Identity.Application" cookie that contains full claims based on `AppUser`
  Note that we can also use `SignInManager`'s `SignOutAsync()` even though it clear other cookies including TwoFactorUserIdScheme cookie (it is deleted in step 2 anyway) and ExternalScheme cookie, but it doesn't delete TwoFactorRememberMeScheme cookie, so it is still safe to use `SignInManager`'s `SignOutAsync()` but it is recommened to have granular control, so better to use `HttpContext.SignOutAsync()`

After SignOut:

if a and d, user only need to enter username and password in the SignIn page, no "SignInTwoFactor" process is needed
if a and c, user not only need to enter username and password in the SignIn page, but also need to enter token in SignInTwoFactor page
if b, then user need to enter username and password in the SignIn page, but also need to enter token in SignInTwoFactor page


## Lockouts and Two-Factor Sign-Ins--------------------------------------------------Ʌ


## Using an Authenticator and Recover Code--------------------------------------------------V

**Time-based One-time Passwords (TOTPs)** is used as an alternative two factor signin methods because  two factor signin method might need cell coverage to receive the token 
while TOTPs only needs Internet access.

The time-based approach works out how many intervals of a fixed duration have occurred since a specific time. The authenticator and Identity will produce the same modifier if they count the number of 3 mins intervals that have occurred since the January 1, 1970, UTC, so no manual synchronization process is required between Identity and authenticatator compared to HMAC-based one-time passwords (HOTPs) which uses a shared counter and need to be synchronized in the first place

The authenticator and Identity both use the same algorithm to generate a code using the shared key (such as "abcd1234") plus a modifier (also known as a moving factor, the number of 3 mins intervals that have occurred since the January 1, 1970, UTC here) that ensures keys are different and cannot be intercepted and reused by an attacker, that's why authenticator will start showing you security codes, **which change every 30 seconds**. 

```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        // ...
        // services.AddSingleton<IUserConfirmation<AppUser>, UserConfirmation>();
        // services.AddSingleton<IUserClaimsPrincipalFactory<AppUser>,  AppUserClaimsPrincipalFactory>();

        services.AddIdentityCore<AppUser>(opts => // opts is IdentityOptions {
            // ...
        })
        .AddTokenProvider<AuthenticatorTokenProvider<AppUser>>(TokenOptions.DefaultAuthenticatorProvider)
        ...

        // ...
    }
}
//------------------Ʌ

//----------------------------V
public partial class UserStore {
    // ...
    public UserStore(ILookupNormalizer normalizer, IPasswordHasher<AppUser> passwordHasher) {
        // ...
        SeedStore();
    }

    private void SeedStore() {
        // ...
        var authenticatorKeys = new Dictionary<string, string> { { "Alice", "A4GG2BNKJNKKFOKGZRGBVUYIAJCUHEW7" } };
        var codes = new[] { "abcd1234", "abcd5678" };

        foreach (string name in UsersAndClaims.Users) {
            AppUser user = new AppUser {
                Id = (++idCounter).ToString(),
                UserName = name,
                // ...
            };

            if (authenticatorKeys.ContainsKey(name))
            {
                user.AuthenticatorKey = authenticatorKeys[name];
                user.AuthenticatorEnabled = true;
            }

            recoveryCodes.Add(user.Id, codes.Select(c => new RecoveryCode() { Code = c }).ToArray());

            users.TryAdd(user.Id, user);
        }
    }
}
//----------------------------Ʌ

//------------------V
public class AppUser
{
    // ...
    public bool AuthenticatorEnabled { get; set; }
    public string AuthenticatorKey { get; set; }  // <--------------private key for third party auth app to generate a code based on the key and timespan
}
//------------------Ʌ

//-----------------------V
public class RecoveryCode
{
    public string Code { get; set; }
    public bool Redeemed { get; set; }
}
//-----------------------Ʌ

//----------------------------V
public partial class UserStore : IUserAuthenticatorKeyStore<AppUser>
{
    public Task<string> GetAuthenticatorKeyAsync(AppUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.AuthenticatorKey);

    public Task SetAuthenticatorKeyAsync(AppUser user, string key, CancellationToken cancellationToken)
    {
        user.AuthenticatorKey = key;
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ

//------------------------------------------------------>>IUserTwoFactorRecoveryCodeStore doest't get all codes for an user but users are more likely to see recovery codes 
public interface IReadableUserTwoFactorRecoveryCodeStore : IUserTwoFactorRecoveryCodeStore<AppUser>  
{
    Task<IEnumerable<RecoveryCode>> GetCodesAsync(AppUser user);
}
//------------------------------------------------------<<

//----------------------------V
public partial class UserStore : IReadableUserTwoFactorRecoveryCodeStore
{
    private IDictionary<string, IEnumerable<RecoveryCode>> recoveryCodes = new Dictionary<string, IEnumerable<RecoveryCode>>();

    public async Task<int> CountCodesAsync(AppUser user, CancellationToken token)
        => (await GetCodesAsync(user)).Where(code => !code.Redeemed).Count();

    public async Task<bool> RedeemCodeAsync(AppUser user, string code, CancellationToken token)
    {
        RecoveryCode rc = (await GetCodesAsync(user)).FirstOrDefault(rc => rc.Code == code && !rc.Redeemed);
        if (rc != null)
        {
            rc.Redeemed = true;
            return true;
        }
        return false;
    }

    public Task ReplaceCodesAsync(AppUser user, IEnumerable<string> recoveryCodes, CancellationToken token)
    {
        this.recoveryCodes[user.Id] = recoveryCodes.Select(rc => new RecoveryCode { Code = rc, Redeemed = false });

        return Task.CompletedTask;
    }

    public Task<IEnumerable<RecoveryCode>> GetCodesAsync(AppUser user) =>
        Task.FromResult(recoveryCodes.ContainsKey(user.Id) ? recoveryCodes[user.Id] : Enumerable.Empty<RecoveryCode>());
}
//----------------------------Ʌ

//----------------------------------V
public class AuthenticatorSetupModel : PageModel
{
    public AuthenticatorSetupModel(UserManager<AppUser> userManager)
        => UserManager = userManager;

    public UserManager<AppUser> UserManager { get; set; }

    [BindProperty(SupportsGet = true)]
    public string Id { get; set; }
    public AppUser AppUser { get; set; }
    public string AuthenticatorUrl { get; set; }

    public async Task OnGetAsync()
    {
        AppUser = await UserManager.FindByIdAsync(Id);
        if (AppUser != null)
        {
            if (AppUser.AuthenticatorKey != null)
            {
                // this is the text that QR code app shows when the QR code is scanned and the authenticator app will use the secret as the key
                AuthenticatorUrl = $"otpauth://totp/ExampleApp:{AppUser.EmailAddress}" + $"?secret={AppUser.AuthenticatorKey}";  // <----------------------
            }
        }
    }

    public async Task<IActionResult> OnPostAsync(string task)
    {
        AppUser = await UserManager.FindByIdAsync(Id);

        if (AppUser != null)
        {
            switch (task)
            {
                case "enable":
                    AppUser.AuthenticatorEnabled = true;
                    AppUser.TwoFactorEnabled = true;
                    break;
                case "disable":
                    AppUser.AuthenticatorEnabled = false;
                    AppUser.TwoFactorEnabled = false;
                    break;
                default:
                    await UserManager.ResetAuthenticatorKeyAsync(AppUser); // <-------------------reset current key to a new security stamp 
                    break;
            }
            await UserManager.UpdateAsync(AppUser);
        }

        return RedirectToPage();
    }
}
//----------------------------------Ʌ

//-------------------------------V
public class SignInTwoFactorModel : PageModel
{
    public SignInTwoFactorModel(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, ISMSSender sender) {
       // ...
    }

    public bool AuthenticatorEnabled { get; set; }

    public async Task OnGet() {
        // ...
    }

    public async Task<IActionResult> OnPost(string code, string rememberMe, [FromQuery] string returnUrl)
    {
        AppUser user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

        if (user != null && !string.IsNullOrEmpty(code))
        {
            SignInResult result = SignInResult.Failed;
            AuthenticatorEnabled = user.AuthenticatorEnabled;
            bool rememberClient = !string.IsNullOrEmpty(rememberMe);

            if (AuthenticatorEnabled)
            {
                string authCode = code.Replace(" ", string.Empty);

                result = await SignInManager.TwoFactorAuthenticatorSignInAsync(authCode, false, rememberClient);  // <---------------------------
            }
            else
            {
                result = await SignInManager.TwoFactorSignInAsync(IdentityConstants.TwoFactorUserIdScheme, code, true, rememberClient);
            }
            // ...
        }
        return Page();
    }
}
//-------------------------------Ʌ

//-----------------------------V
public class RecoveryCodesModel : PageModel
{
    public RecoveryCodesModel(UserManager<AppUser> manager, IUserStore<AppUser> store)
    {
        UserManager = manager;
        UserStore = store;
    }
    public UserManager<AppUser> UserManager { get; set; }
    public IUserStore<AppUser> UserStore { get; set; }
    public AppUser AppUser { get; set; }
    public RecoveryCode[] Codes { get; set; }
    public int RemainingCodes { get; set; }

    public async Task OnGetAsync(string id)
    {
        AppUser = await UserManager.FindByIdAsync(id);
        if (AppUser != null)
        {
            Codes = (await GetCodes()).OrderBy(c => c.Code).ToArray();
            RemainingCodes = await UserManager.CountRecoveryCodesAsync(AppUser);  // <---------------------------
        }
    }

    public async Task<IActionResult> OnPostAsync(string id)
    {
        AppUser = await UserManager.FindByIdAsync(id);

        await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(AppUser, 10);  // <------------------------------

        return RedirectToPage();
    }

    private async Task<IEnumerable<RecoveryCode>> GetCodes()
    {
        if (UserStore is IReadableUserTwoFactorRecoveryCodeStore)
        {
            return await (UserStore as IReadableUserTwoFactorRecoveryCodeStore).GetCodesAsync(AppUser);  // <------------------------
        }

        return Enumerable.Empty<RecoveryCode>();
    }
}
//-----------------------------Ʌ

//----------------------------------V there is a link on TwoFactor SignIn page that redirect users to enter recovery code in this page
public class SignInRecoveryCodeModel : PageModel 
{
    public SignInRecoveryCodeModel(SignInManager<AppUser> manager)
        => SignInManager = manager;

    public SignInManager<AppUser> SignInManager { get; set; }

    public async Task<IActionResult> OnPostAsync(string code, string returnUrl)
    {
        if (string.IsNullOrEmpty(code))
        {
            ModelState.AddModelError("", "Code required");
        }
        else
        {
            SignInResult result = await SignInManager.TwoFactorRecoveryCodeSignInAsync(code);  // <-----------------------
            if (result.Succeeded)
            {
                return Redirect(returnUrl ?? "/");
            }
            else
            {
                ModelState.AddModelError("", "Sign In Failed");
            }
        }
        return Page();
    }
}
//----------------------------------Ʌ
```

## Using an Authenticator and Recover Code--------------------------------------------------Ʌ


## External Authentication Prerequisite--------------------------------------------------V

```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        // ...
       services.AddAuthentication(opts => {  // opts is AuthenticationOptions
          opts.DefaultScheme = IdentityConstants.ApplicationScheme;
          opts.AddScheme<ExternalAuthHandler>("demoAuth", "Demo Service");  // <------------------------------
       })
       .AddCookie(IdentityConstants.ApplicationScheme, opts => {
           opts.LoginPath = "/signin";
        opts.AccessDeniedPath = "/signin/403";
       })
       .AddCookie(IdentityConstants.TwoFactorUserIdScheme)
       .AddCookie(IdentityConstants.TwoFactorRememberMeScheme)
       .AddCookie(IdentityConstants.ExternalScheme);  // <----------------------------
    }
}
//------------------Ʌ

//------------------V
public class AppUser
{
    // ...
    public IList<UserLoginInfo> UserLogins { get; set; }  // <---------------------
}
//------------------Ʌ

//----------------------------V
public partial class UserStore : IUserLoginStore<AppUser>
{
    public Task<IList<UserLoginInfo>> GetLoginsAsync(AppUser user, CancellationToken token) =>
         Task.FromResult(user.UserLogins ?? new List<UserLoginInfo>());

    public Task AddLoginAsync(AppUser user, UserLoginInfo login, CancellationToken token)
    {
        if (user.UserLogins == null)
        {
            user.UserLogins = new List<UserLoginInfo>();
        }

        user.UserLogins.Add(login);

        return Task.CompletedTask;
    }

    public async Task RemoveLoginAsync(AppUser user, string loginProvider, string providerKey, CancellationToken token)
    {
        user.UserLogins =
            (await GetLoginsAsync(user, token))
            .Where(login => !login.LoginProvider.Equals(loginProvider) && !login.ProviderKey.Equals(providerKey)).ToList();
    }

    public Task<AppUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken token)
    {
        return Task.FromResult(
            Users.FirstOrDefault(u =>
                u.UserLogins != null && u.UserLogins.Any(login => login.LoginProvider.Equals(loginProvider) && login.ProviderKey.Equals(providerKey))));
    }
}
//----------------------------Ʌ

/* SignIn Page where users the button "Demo Service" 
<form method="post">  // <----------------------------------e0
    <h4>External Authentication</h4>
    <div class="mt-4 w-75">
        @foreach (var scheme in await Model.SignInManager.GetExternalAuthenticationSchemesAsync()) 
        {
            <div class="mt-2 text-center">
                <button class="btn btn-block btn-secondary m-1 mx-5" type="submit"
                        asp-page="/externalsignin"                                  // <----------------------------------e0
                        asp-route-returnUrl="@Request.Query["returnUrl"]"
                        asp-route-providername="@scheme.Name">
                    @scheme.DisplayName
                </button>
            </div>
        }
    </div>
</form>
*/

//------------------------------V
public class ExternalAuthHandler : IAuthenticationHandler
{
    public AuthenticationScheme Scheme { get; set; }
    public HttpContext Context { get; set; }

    public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
    {
        Scheme = scheme;
        Context = context;
        return Task.CompletedTask;
    }

    public Task<AuthenticateResult> AuthenticateAsync()
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }

    public async Task ChallengeAsync(AuthenticationProperties properties)  // <--------------------------e2.0
    {
        ClaimsIdentity identity = new ClaimsIdentity(Scheme.Name);
        identity.AddClaims(new[] {
                new Claim(ClaimTypes.NameIdentifier, "SomeUniqueID"),  // <--------use an id that doesn't exist in user store
                new Claim(ClaimTypes.Email, "alice@example.com"),      // to demostrate how we can associate email with local account
                new Claim(ClaimTypes.Name, "Alice")
            });
        ClaimsPrincipal principal = new ClaimsPrincipal(identity);

        await Context.SignInAsync(IdentityConstants.ExternalScheme, principal, properties);  // <--------------------------e2.1

        Context.Response.Redirect(properties.RedirectUri);  // <-------------------e2.2. RedirectUri is "/ExternalSignIn?returnUrl=%2F&handler=Correlate"
    }

    public Task ForbidAsync(AuthenticationProperties properties)
    {
        return Task.CompletedTask;
    }
}
//------------------------------Ʌ

//------------------------------V
public class ExternalSignInModel : PageModel
{
    public ExternalSignInModel(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager)
    {
        SignInManager = signInManager;
        UserManager = userManager;
    }

    public SignInManager<AppUser> SignInManager { get; set; }
    public UserManager<AppUser> UserManager { get; set; }

    public string ProviderDisplayName { get; set; }

    public IActionResult OnPost(string providerName, string returnUrl = "/")  // <-----------------------------e1 providerName is demoAuth
    {
        // redirectUrl is "/ExternalSignIn?returnUrl=%2F&handler=Correlate"
        string redirectUrl = Url.Page("./ExternalSignIn", pageHandler: "Correlate", values: new { returnUrl });

        AuthenticationProperties properties = SignInManager.ConfigureExternalAuthenticationProperties(providerName, redirectUrl);  // <-----------------e1.1

        return new ChallengeResult(providerName, properties);  // <-----------------e1.2. providerName will be used as scheme name, check ChallengeResult.ExecuteResultAsync()
    }

    // this is the "Correlate" phrase in external authentication that "correlate" external users info with application's local user info
    public async Task<IActionResult> OnGetCorrelate(string returnUrl)  // <--------------------------e3.
    {
        ExternalLoginInfo loginInfo = 
            await SignInManager.GetExternalLoginInfoAsync();  // <---------------call Context.AuthenticateAsync(IdentityConstants.ExternalScheme) internally 
                                                              // to "get" the result from external IAuthenticationHandler.ChallengeAsync() 
                                                              // which calls Context.SignInAsync(IdentityConstants.ExternalScheme, principal, properties);

        AppUser user = await UserManager.FindByLoginAsync(loginInfo.LoginProvider, loginInfo.ProviderKey);  // providerKey is the value of ClaimTypes.NameIdentifier

        if (user == null)
        {
            string externalEmail = loginInfo.Principal.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;
            user = await UserManager.FindByEmailAsync(externalEmail);
            if (user == null)
            {
                return RedirectToPage("/ExternalAccountConfirm", new { returnUrl });
            }
            else
            {
                await UserManager.AddLoginAsync(user, loginInfo);  // associate the login in the store and sign the user into the application
            }
        }

        // SignInManager.ExternalLoginSignInAsync check login by internally calling UserManager.FindByLoginAsync(loginProvider, providerKey)
        SignInResult result = await SignInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, false, false);  // <-----------------
        if (result.Succeeded)
        {
            return RedirectToPage("ExternalSignIn", "Confirm", new { loginInfo.ProviderDisplayName, returnUrl });
        }
        else if (result.RequiresTwoFactor)
        {
            // postSignInUrl is "/ExternalSignIn?ProviderDisplayName=Demo%20Service&returnUrl=%2F&handler=Confirm"
            string postSignInUrl = this.Url.Page("/ExternalSignIn", "Confirm", new { loginInfo.ProviderDisplayName, returnUrl });

            return RedirectToPage("/SignInTwoFactor", new { returnUrl = postSignInUrl });
        }

        return RedirectToPage(new { error = true, returnUrl });
    }

    public async Task OnGetConfirmAsync()
    {
        string provider = User.FindFirstValue(ClaimTypes.AuthenticationMethod);

        ProviderDisplayName = (await SignInManager.GetExternalAuthenticationSchemesAsync()).FirstOrDefault(s => s.Name == provider)?.DisplayName ?? provider;
    }
}
//------------------------------Ʌ
```

## External Authentication Prerequisite--------------------------------------------------Ʌ



## External Authentication Simulated--------------------------------------------------V

To see why both authCode and access token are needed, why not just pass access token directly, check ee3.1

```C#
//------------------------------V  services.AddOptions<ExternalAuthOptions>();
public class ExternalAuthOptions
{
    public string ClientId { get; set; } = "MyClientID";
    public string ClientSecret { get; set; } = "MyClientSecret";

    public virtual string RedirectRoot { get; set; } = "http://localhost:5000";
    public virtual string RedirectPath { get; set; } = "/signin-external";
    public virtual string Scope { get; set; } = "openid email profile";
    public virtual string StateHashSecret { get; set; } = "mysecret";
    public virtual string AuthenticationUrl { get; set; } = "http://localhost:5000/DemoExternalAuth/authenticate";
    public virtual string ExchangeUrl { get; set; } = "http://localhost:5000/DemoExternalAuth/exchange";
    public virtual string ErrorUrlTemplate { get; set; } = "/externalsignin?error={0}";
    public virtual string DataUrl { get; set; } = "http://localhost:5000/DemoExternalAuth/data";
}
//------------------------------Ʌ

//------------------------------V
public class ExternalAuthHandler : IAuthenticationRequestHandler
{
    public ExternalAuthHandler(IOptions<ExternalAuthOptions> options, IDataProtectionProvider dp, ILogger<ExternalAuthHandler> logger)
    {
        Options = options.Value;
        DataProtectionProvider = dp;
        Logger = logger;
    }

    public AuthenticationScheme Scheme { get; set; }
    public HttpContext Context { get; set; }
    public ExternalAuthOptions Options { get; set; }

    public IDataProtectionProvider DataProtectionProvider { get; set; }
    public PropertiesDataFormat PropertiesFormatter { get; set; }
    public ILogger<ExternalAuthHandler> Logger { get; set; }
    public string ErrorMessage { get; set; }


    public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
    {
        Scheme = scheme;
        Context = context;
        PropertiesFormatter = new PropertiesDataFormat(DataProtectionProvider.CreateProtector(typeof(ExternalAuthOptions).FullName));
        return Task.CompletedTask;
    }

    public Task<AuthenticateResult> AuthenticateAsync()  // doesn't do authentication as you want external auth service does the job
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }

    public async Task ChallengeAsync(AuthenticationProperties properties)  // < ----------ee1.2 note that there are three different "return url" here,  
    {                                                                      // one is "DemoExternalAuth/authenticate?xxx" that need to be redirected immediately.
                                                                           // The other one is AuthenticationProperties.RedirectUri to be used later. The last one is
                                                                           //  "secret" route inside as a segment of AuthenticationProperties.RedirectUri  
                                                                                                                               
        Context.Response.Redirect(await GetAuthenticationUrl(properties));  // <--------------------------------ee1.3.
        /* redirect to      
        DemoExternalAuth/authenticate?client_id=MyClientID&redirect_uri=localhost:5000/signin-external&scope=openid%20email%20profile&response_type=code&state=xxx
        AuthenticationProperties properties contains return url which is "/ExternalSignIn?returnUrl=secret%2F&handler=Correlate" which is encrypted

        For Google:
        https://accounts.google.com/o/oauth2/v2/auth?client_id=396623271087-1lvqvq0v71bennoicj3q8ns8l5jk825m.apps.googleusercontent.com&redirect_uri=localhost%3A5000%2Fsignin-google&scope=openid%20email%20profile&response_type=code&state=xxx
        Google will redirect it to:
        https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?client_id=396623271087-1lvqvq0v71bennoicj3q8ns8l5jk825m.apps.googleusercontent.com&redirect_uri=localhost%3A5000%2Fsignin-google&scope=openid%20email%20profile&response_type=code&state=xxx&service=lso&o2v=2&theme=glif&flowName=GeneralOAuthFlow
        */

    }

    protected virtual Task<string> GetAuthenticationUrl(AuthenticationProperties properties)
    {
        Dictionary<string, string> qs = new Dictionary<string, string>();

        qs.Add("client_id", Options.ClientId);
        qs.Add("redirect_uri", Options.RedirectRoot + Options.RedirectPath);  // RedirectPath is "signin-external"
        qs.Add("scope", Options.Scope);
        qs.Add("response_type", "code");
        qs.Add("state", PropertiesFormatter.Protect(properties));

        return Task.FromResult(Options.AuthenticationUrl + QueryString.Create(qs));
    }

    public virtual async Task<bool> HandleRequestAsync()  // <----------------ee4.0 intercept the "xxx/signin-external" request which is initialized by Google as below
    {                                                     // http://localhost:5000/signin-google?state=xxx&code=yyy&scope=email+profile+zzz&authuser=0&prompt=none
        if (Context.Request.Path.Equals(Options.RedirectPath)) // when RedirectPath is "signin-external", literally it can be any url? must be another good approach?
        {
            string authCode = Context.Request.Query["code"].ToString();  // authCode is sent by externl service
            (string token, string state) = await GetAccessToken(authCode);  // <-----------ee4.1 exchanging the Authorization Code for an Access Token
            if (!string.IsNullOrEmpty(token))
            {
                IEnumerable<Claim> claims = await GetUserData(token);  // <----------ee5.0 use access token to get user data from external auth service
                if (claims != null)
                {
                    ClaimsIdentity identity = new ClaimsIdentity(Scheme.Name);  // Scheme.Name is "Google"
                    identity.AddClaims(claims);
                    ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);
                    AuthenticationProperties props = PropertiesFormatter.Unprotect(state);

                    await Context.SignInAsync(IdentityConstants.ExternalScheme, claimsPrincipal, props);  // <--------------! ee6, call Context.SignInAsync here, compared to
                                                                                                          // before SignIn is called in ExternalAuthHandler.ChallengeAsync()
                    Context.Response.Redirect(props.RedirectUri);  // RedirectUri is "/ExternalSignIn?returnUrl=%2F&handler=Correlate"

                    return true;
                }
            }

            Context.Response.Redirect(string.Format(Options.ErrorUrlTemplate, ErrorMessage));

            return true;
        }

        return false;
    }

    protected virtual async Task<(string token, string state)> GetAccessToken(string authCode)
    {
        string state = Context.Request.Query["state"];
        HttpClient httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        HttpResponseMessage response = await httpClient.PostAsJsonAsync(  // <----------------ee4.2 call external service's Exchange handler
            Options.ExchangeUrl, // <-----------                                        
            new
            {
                code = authCode,   // <---------------
                redirect_uri = Options.RedirectRoot + Options.RedirectPath,
                client_id = Options.ClientId,
                client_secret = Options.ClientSecret, // <------------provider secret to get access token, note that secret is not needed in getting user data process
                state,
                grant_type = "authorization_code",
            }
        );

        string jsonData = await response.Content.ReadAsStringAsync();
        JsonDocument jsonDoc = JsonDocument.Parse(jsonData);
        string error = jsonDoc.RootElement.GetString("error");

        if (error != null)
        {
            ErrorMessage = "Access Token Error";
            Logger.LogError(ErrorMessage);
            Logger.LogError(jsonData);
        }

        string token = jsonDoc.RootElement.GetString("access_token");    // <----------------ee4.3. get access token
        string jsonState = jsonDoc.RootElement.GetString("state") ?? state;

        return error == null ? (token, state) : (null, null);
    }

    public Task ForbidAsync(AuthenticationProperties properties)
    {
        return Task.CompletedTask;
    }

    protected virtual async Task<IEnumerable<Claim>> GetUserData(string accessToken)
    {
        HttpRequestMessage msg = new HttpRequestMessage(HttpMethod.Get, Options.DataUrl);  // <----------invoke external service's Data handler
        msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);  // <----------head will be e.g "Bearer xxx", do not need client_secret
        HttpResponseMessage response = await new HttpClient().SendAsync(msg);

        string jsonData = await response.Content.ReadAsStringAsync();   // <----------------ee5.1.

        JsonDocument jsonDoc = JsonDocument.Parse(jsonData);

        var error = jsonDoc.RootElement.GetString("error");
        if (error != null)
        {
            ErrorMessage = "User Data Error";
            Logger.LogError(ErrorMessage);
            Logger.LogError(jsonData);
            return null;
        }
        else
        {
            return GetClaims(jsonDoc);
        }
    }

    protected virtual IEnumerable<Claim> GetClaims(JsonDocument jsonDoc)
    {
        List<Claim> claims = new List<Claim>();
        claims.Add(new Claim(ClaimTypes.NameIdentifier, jsonDoc.RootElement.GetString("id")));
        claims.Add(new Claim(ClaimTypes.Name, jsonDoc.RootElement.GetString("name")));
        claims.Add(new Claim(ClaimTypes.Email, jsonDoc.RootElement.GetString("emailAddress")));

        return claims;
    }
}
//------------------------------Ʌ

//-------------------------------------V
public class DemoExternalAuthController : Controller  // demonstrate external authentication, you can consider it as Google Auth Service
{
    private static string expectedID = "MyClientID";
    private static string expectedSecret = "MyClientSecret";
    private static List<UserRecord> users = new List<UserRecord> {  // simulate gmail account
            new UserRecord()
            {
                Id = "1", Name = "Alice", EmailAddress = "alice@example.com", Password = "myexternalpassword",
                Code = "12345", Token = "token1"
            },
            new UserRecord
            {
                Id = "2", Name = "Dora", EmailAddress = "dora@example.com", Password = "myexternalpassword",
                Code = "56789", Token = "token2"
            }
        };

    public IActionResult Authenticate([FromQuery] ExternalAuthInfo info)  // <-----------------ee2.0, simulate Googe's SignIn page
    {
        return expectedID == info.client_id ? View((info, string.Empty)) : View((info, "Unknown Client"));
        /* < -----------------ee2.1.
         this Razor View prompt user to enter user name and password and then make a post request to the below handler
         with all value of ExternalAuthInfo are hidden as input
        */
    }

    [HttpPost]
    public IActionResult Authenticate(ExternalAuthInfo info, string email, string password)  //<-----------------ee3.0 when you click SignIn button simulate
    {                                                                                        // the post request for Googe's verification after users enter credentials
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        {
            ModelState.AddModelError("", "Email and password required");
        }
        else
        {
            UserRecord user = users.FirstOrDefault(u => u.EmailAddress.Equals(email) && u.Password.Equals(password));  // find whether the user exist in Google's database

            if (user != null)
            {
                // localhost:5000/signin-external?code=12345&scope=openid email profile&state=xxx_
                //For Google, redirect_uri needs to be pre registered when configuring Google's OAuth
                return  Redirect(info.redirect_uri + $"?code={user.Code}&scope={info.scope}" + $"&state={info.state}");  //<------------------------------------------ee3.1.
                /* why OAuth need an extra that use both authCode and access token, why not just use access token
                because OAuth like Google need to redirect user to an URL that will be intercepted by application's server(IAuthenticationRequestHandler.HandleRequestAsync())
                this make the user's browser invloved with explict access token displayed in browser history that can be intercepted by attacker.
                Using an extra layer of authCode, it is now the application server uses the authCode along with application's clientId and secret to make a post request to 
                Google auth service, so it doesn't involved user's browser therefore it is more secure
                */
            }
            else
            {
                ModelState.AddModelError("", "Email or password incorrect");
            }
        }

        return View((info, ""));

    }

    [HttpPost]
    public IActionResult Exchange([FromBody] ExternalAuthInfo info)
    {
        UserRecord user = users.FirstOrDefault(user => user.Code.Equals(info.code));  // get user by auth code, but external servcie won't pass user'data in this step

        if (user == null || info.client_id != expectedID || info.client_secret != expectedSecret)
        {
            return Json(new { error = "unauthorized_client" });
        }
        else
        {
            return Json(new
            {
                access_token = user.Token,
                expires_in = 3600,
                scope = "openid+email+profile",
                token_type = "Bearer",
                info.state
            });
        }
    }

    [HttpGet]
    /*  initialize request
    GET HTTP/1.1
    Host: xxx
    Accept: application/json
    Authorization: Bearer token1
    */
    public IActionResult Data([FromHeader] string authorization)  // authorization is "Bearer token1"
    {
        string token = authorization?[7..];
        UserRecord user = users.FirstOrDefault(user => user.Token.Equals(token));  // get user by token and pass user's data
        if (user != null)
        {
            return Json(new { user.Id, user.EmailAddress, user.Name });
        }
        else
        {
            return Json(new { error = "invalid_token" });
        }
    }
}
//-------------------------------------Ʌ
public class UserRecord
{
    public string Id { get; set; }
    public string Name { get; set; }
    public string EmailAddress { get; set; }
    public string Password { get; set; }
    public string Code { get; set; }  // authorization code tells the request initiated application that the user 
                                      // has been authenticated and has granted access to the data specified by the scope
    public string Token { get; set; }
}

public class ExternalAuthInfo
{
    public string client_id { get; set; }
    public string client_secret { get; set; }
    public string redirect_uri { get; set; }
    public string scope { get; set; }
    public string state { get; set; }
    public string response_type { get; set; }
    public string grant_type { get; set; }
    public string code { get; set; }
}

```

## External Authentication Simulated--------------------------------------------------Ʌ



## External Authentication (Google)--------------------------------------------------V

```C#
//------------------V
public class Startup
{

    public void ConfigureServices(IServiceCollection services)
    {
        // ...   
        services.Configure<GoogleOptions>(opts => { 
            opts.ClientId = "ReplaceMe";  // use real client id and client secret here
            opts.ClientSecret = "ReplaceMe";
        });

        services.AddAuthentication(opts => {
            opts.DefaultScheme = IdentityConstants.ApplicationScheme;
            //opts.AddScheme<ExternalAuthHandler>("demoAuth", "Demo Service");
            opts.AddScheme<GoogleHandler>("google", "Google");
        })
        // ...
    }
}
//------------------Ʌ

//------------------>>
public class AppUser
{
    // ...
    public IList<UserLoginInfo> UserLogins { get; set; }

    public IList<(string provider, AuthenticationToken token)> AuthTokens { get; set; }  // <-----------------
}
//------------------<<

//----------------------------V
public partial class UserStore : IUserAuthenticationTokenStore<AppUser>
{
    public Task<string> GetTokenAsync(AppUser user, string loginProvider, string name, CancellationToken cancelToken)
    {
        return Task.FromResult(user.AuthTokens?.FirstOrDefault(t => t.provider == loginProvider && t.token.Name == name).token.Value);
    }

    public Task RemoveTokenAsync(AppUser user, string loginProvider, string name, CancellationToken cancelToken)
    {
        if (user.AuthTokens != null)
        {
            user.AuthTokens = user.AuthTokens.Where(t => t.provider != loginProvider && t.token.Name != name).ToList();
        }
        return Task.CompletedTask;
    }

    public Task SetTokenAsync(AppUser user, string loginProvider, string name, string value, CancellationToken cancelToken)
    {
        if (user.AuthTokens == null)
        {
            user.AuthTokens = new List<(string, AuthenticationToken)>();
        }

        user.AuthTokens.Add((loginProvider, new AuthenticationToken
        {
            Name = name,
            Value = value
        }));
        return Task.CompletedTask;
    }
}
//----------------------------Ʌ
```

```C#
//------------------------>>
public class GoogleOptions : ExternalAuthOptions
{
    public override string RedirectPath { get; set; } = "/signin-google";
    public override string AuthenticationUrl => "https://accounts.google.com/o/oauth2/v2/auth";
    public override string ExchangeUrl => "https://www.googleapis.com/oauth2/v4/token";
    public override string DataUrl => "https://www.googleapis.com/oauth2/v2/userinfo";
}
//------------------------<<

//------------------------V
public class GoogleHandler : ExternalAuthHandler
{
    public GoogleHandler(IOptions<GoogleOptions> options, IDataProtectionProvider dp, ILogger<GoogleHandler> logger) : base(options, dp, logger) { }

    protected override IEnumerable<Claim> GetClaims(JsonDocument jsonDoc)
    {
        List<Claim> claims = new List<Claim>();
        claims.Add(new Claim(ClaimTypes.NameIdentifier, jsonDoc.RootElement.GetString("id")));
        claims.Add(new Claim(ClaimTypes.Name, jsonDoc.RootElement.GetString("name")?.Replace(" ", "_")));
        claims.Add(new Claim(ClaimTypes.Email, jsonDoc.RootElement.GetString("email")));

        return claims;
    }

    protected async override Task<string> GetAuthenticationUrl(AuthenticationProperties properties)
    {
        if (CheckCredentials())
        {
            return await base.GetAuthenticationUrl(properties);
        }
        else
        {
            return string.Format(Options.ErrorUrlTemplate, ErrorMessage);
        }
    }

    private bool CheckCredentials()
    {
        string secret = Options.ClientSecret;
        string id = Options.ClientId;
        string defaultVal = "ReplaceMe";
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(id) || defaultVal.Equals(secret) || defaultVal.Equals(secret))
        {
            ErrorMessage = "External Authentication Secret or ID Not Set";
            Logger.LogError("External Authentication Secret or ID Not Set");
            return false;
        }

        return true;
    }
}
//------------------------Ʌ
```

```json
{
  "web": {
    "client_id": "xxx*.apps.googleusercontent.com",
    "project_id": "exampleapp-410023",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "xxx*",
    "redirect_uris": [ "http://localhost:5000/signin-google" ]
  }
}
// code/authCode: 4/0AfJohXlneOgAu_yfrh4Uwqxp-Oine0BzRpDgRe7uzeZtsUg_bjKf5ZkRmKEw9jcCV2Bggg
// token: ya29.a0AfB_byDlqldgqORHc3hVfbfdJJXqdFhkHgK4aNYyexX2Rqwk9VvVAUoQYQ1BJLVjCvUkZM8tM8Pc3zg2XeuilAni5QzyCpB10wA_aQG1hibTY0W4VQd9C10RNWeZVAceBvRqZZjlp7S62G3vo2LqwTYhRXDiCSkWT0TEaCgYKAbASARASFQHGX2MiZSPrDXQa_l9qmPZhx84CMw0171
```
## External Authentication (Google)--------------------------------------------------Ʌ

