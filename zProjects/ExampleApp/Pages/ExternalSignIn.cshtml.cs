using ExampleApp.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace ExampleApp.Pages
{
    public class ExternalSignInModel : PageModel
    {
        public ExternalSignInModel(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager)
        {
            SignInManager = signInManager;
            UserManager = userManager;
        }

        public SignInManager<AppUser> SignInManager { get; set; }
        public UserManager<AppUser> UserManager { get; set; }

        public string ProviderDisplayName {  get; set; }

        // this is the handler when user click the button for external sign in such as "SignIn by Google"
        public IActionResult OnPost(string providerName, string returnUrl = "/")  // providerName is demoAuth <-----------------ee1
        {
            // redirectUrl is "/ExternalSignIn?returnUrl=secret%2F&handler=Correlate"
            string redirectUrl = Url.Page("./ExternalSignIn", pageHandler: "Correlate", values: new { returnUrl });

            AuthenticationProperties properties = SignInManager.ConfigureExternalAuthenticationProperties(providerName, redirectUrl);

            return new ChallengeResult(providerName, properties);  // < -----------------ee1.1
        }

        public async Task<IActionResult> OnGetCorrelate(string returnUrl)
        {
            ExternalLoginInfo loginInfo = 
                await SignInManager.GetExternalLoginInfoAsync();  // <-------------------call Context.AuthenticateAsync(IdentityConstants.ExternalScheme) internally to "get" the result from
                                                                  // external IAuthenticationHandler.ChallengeAsync() calls Context.SignInAsync(IdentityConstants.ExternalScheme, principal, properties);

            // note that loginInfo.ProviderKey is the prmiary key of the users in external service, not the application's primary key for our AppUser
            // maybe that's the reason we need to store it? need to work more to see how FindByLoginAsync acheive it purpose
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
            SignInResult result = await SignInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, false, false);

            await SignInManager.UpdateExternalAuthenticationTokensAsync(loginInfo);

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
            string provider = User.FindFirstValue(ClaimTypes.AuthenticationMethod);  // AuthenticationMethod is "demoAuth"

            ProviderDisplayName = (await SignInManager.GetExternalAuthenticationSchemesAsync()).FirstOrDefault(s => s.Name == provider)?.DisplayName ?? provider;
        }
    }
}
