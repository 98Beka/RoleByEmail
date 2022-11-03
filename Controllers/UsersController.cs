
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CustomIdentityApp.Controllers {
    public class UsersController : Controller {
        UserManager<IdentityUser> _userManager;

        public UsersController(UserManager<IdentityUser> userManager) {
            _userManager = userManager;
        }

        public IActionResult Index() => View(_userManager.Users.ToList());

        public async Task<IActionResult> Admins() =>
            View(await _userManager.GetUsersInRoleAsync("admin"));

        [HttpPost]
        public async Task<ActionResult> Delete(string id) {
            IdentityUser user = await _userManager.FindByIdAsync(id);
            if (user != null) {
                IdentityResult result = await _userManager.DeleteAsync(user);
            }
            return RedirectToAction("Index");
        }
    }
}
