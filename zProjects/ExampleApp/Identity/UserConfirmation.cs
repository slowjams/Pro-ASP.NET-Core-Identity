using ExampleApp.Identity;
using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading.Tasks;

namespace ExampleApp.Identity
{
    public class UserConfirmation : IUserConfirmation<AppUser> // <-----------------used by SignInManager's PreSignInCheck -> CanSignInAsync
    {
        public async Task<bool> IsConfirmedAsync(UserManager<AppUser> manager, AppUser user)
        {
            return await manager
                .IsInRoleAsync(user, "Administrator") || (await manager.GetClaimsAsync(user))
                .Any(claim => claim.Type == "UserConfirmed" && 
                string.Compare(claim.Value, "true", true) == 0);
        }
    }
}
