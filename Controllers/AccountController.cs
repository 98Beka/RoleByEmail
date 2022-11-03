using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using RolesByEmail.ViewModels;

namespace CustomIdentityApp.Controllers {
    public class AccountController : Controller {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager) {
            _userManager = userManager;
            _signInManager = signInManager;
        }
        [HttpGet]
        public IActionResult Register() {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model) {
            if (ModelState.IsValid) {
                IdentityUser user = new IdentityUser { Email = model.Email, UserName = model.Email};
                // добавляем пользователя
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded) {
                    // установка куки
                    await _signInManager.SignInAsync(user, false);
                    return RedirectToAction("Index", "Home");
                } else {
                    foreach (var error in result.Errors) {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Login() {
            return View(new LoginViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model) {
                var result =
                    await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
                if (result.Succeeded) {
                    // проверяем, принадлежит ли URL приложению

                        return RedirectToAction("Index", "Home");
                } else {
                    ModelState.AddModelError("", "Неправильный логин и (или) пароль");
                }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout() {
            // удаляем аутентификационные куки
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        public async Task<IActionResult> AccessDenied() {
            IdentityUser user = await _userManager.FindByEmailAsync(this.User.Identity.Name);
            return View(await _userManager.GetRolesAsync(user));
        }


        public async Task<IActionResult> AddToAdmins(string email) {
            if (string.IsNullOrEmpty(email))
                ModelState.AddModelError("", "адресс электронной почты не введен");
            IdentityUser user = await _userManager.FindByEmailAsync(email) ;
            if (user == null)
                ModelState.AddModelError("", "Такой пользователь незарегистрирован");
            await _userManager.AddToRoleAsync(user, "admin");
            return RedirectToAction("Admins", "Users");
        }

        public async Task<IActionResult> RemoveFromAdmins(string email) {
            if (string.IsNullOrEmpty(email)) {
                ModelState.AddModelError("", "адресс электронной почты не введен");
                return RedirectToAction("Admins", "Users");
            }
            IdentityUser user = await _userManager.FindByEmailAsync(email);
            if (user == null) {
                ModelState.AddModelError("", "Такой пользователь незарегистрирован");
                return RedirectToAction("Admins", "Users");
            }
            await _userManager.RemoveFromRoleAsync(user, "admin");
            return RedirectToAction("Admins", "Users");
        }
    }
}
 