using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace ExampleApp.Identity
{
    public class RoleValidator : IRoleValidator<AppRole>
    {
        public static IdentityError error = new IdentityError { Description = "Names cannot be plural/singular of existing roles"};

        public async Task<IdentityResult> ValidateAsync(RoleManager<AppRole> roleManager, AppRole role)
        {
            if (await roleManager.FindByNameAsync(role.Name.EndsWith("s") ? role.Name[0..^1] : role.Name + "s") == null)
            {
                return IdentityResult.Success;
            }
            return IdentityResult.Failed(error);
        }
    }
}
