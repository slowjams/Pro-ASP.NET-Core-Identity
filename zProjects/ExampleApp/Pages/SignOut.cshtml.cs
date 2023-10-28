using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using ExampleApp.Identity;
using System;

namespace ExampleApp.Pages
{
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
                await SignInManager.ForgetTwoFactorClientAsync();  // calls Context.SignOutAsync(IdentityConstants.TwoFactorRememberMeScheme) to clear the relevent cookie
            }
            
            await HttpContext.SignOutAsync();  // do not use the SignInManager<T>.SignOutAsync method to sign out of the application because
                                               // it will throw an exception, reporting there is no handler for the external scheme.
            
            return RedirectToPage("SignIn");
        }
    }
}