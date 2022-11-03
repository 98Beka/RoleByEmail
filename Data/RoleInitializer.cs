using Microsoft.AspNetCore.Identity;

namespace RolesByEmail.Data {
    public class RoleInitializer {
        public static async Task InitializeAsync(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager,
            IdentityUser superAdmin, string superAdminPassword) {
            if (await roleManager.FindByNameAsync("admin") == null) {
                await roleManager.CreateAsync(new IdentityRole("admin"));
            }
            if (await roleManager.FindByNameAsync("superAdmin") == null) {
                await roleManager.CreateAsync(new IdentityRole("superAdmin"));
            }
            if (await userManager.FindByEmailAsync(superAdmin.Email) == null) {
                IdentityResult result = await userManager.CreateAsync(superAdmin, superAdminPassword);
                if (result.Succeeded) {
                    await userManager.AddToRoleAsync(superAdmin, "superAdmin");
                    await userManager.AddToRoleAsync(superAdmin, "admin");
                }
            }
        }
    }
}
