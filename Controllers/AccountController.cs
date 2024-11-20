using IdentityApp.Models;
using IdentityApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class AccountController : Controller
    {
        private UserManager<AppUser> _userManager;
        private RoleManager<AppRole> _roleManager;
        private SignInManager<AppUser> _signInManager;
        private IEmailSender _emailSender;

        public AccountController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager, SignInManager<AppUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    await _signInManager.SignOutAsync();
                    if (!await _userManager.IsEmailConfirmedAsync(user))
                    {
                        ModelState.AddModelError("", "Hesabınızı Onaylayınız.");
                        return View(model);
                    }
                    var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, true);
                    if (result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _userManager.SetLockoutEndDateAsync(user, null);

                        return RedirectToAction("Index", "Home");
                    }
                    else if (result.IsLockedOut)
                    {
                        var lockoutDate = await _userManager.GetLockoutEndDateAsync(user);
                        var timeLeft = lockoutDate.Value - DateTime.UtcNow;
                        ModelState.AddModelError("", $"Hesabınız Kitlendi, Lütfen giriş yapmadan {timeLeft.Minutes} dakika bekleyiniz");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Hatalı  Parola");

                    }
                }
                else
                {
                    ModelState.AddModelError("", "Hatalı Email ");
                }
            }
            return View(model);
        }





        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Create(CreateViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new AppUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    FullName = model.FullName
                };

                if (string.IsNullOrEmpty(model.Password))
                {
                    ModelState.AddModelError("Password", "Password cannot be null or empty.");
                    return View(model);
                }

                IdentityResult result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var url = Url.Action("ConfirmEmail", "Account", new { user.Id, token });

                    await _emailSender.SendEmailAsync(user.Email, "Hesap Onayı", $"Lütfen email hesabınızı onaylamak için linke <a href='http://localhost:5019{url}'>tıklayınız</a>.");



                    TempData["message"] = "Email hesabınıza gelen Onay mailine tıklayınız";

                    return RedirectToAction("Login", "Account");
                }

                foreach (IdentityError err in result.Errors)
                {
                    ModelState.AddModelError("", err.Description);
                }
            }
            return View(model);
        }


        public async Task<IActionResult> ConfirmEmail(string Id, string token)
        {
            if (Id == null || token == null)
            {
                TempData["message"] = "Geçersiz Token Bilgisi";
                return View();
            }
            var user = await _userManager.FindByIdAsync(Id);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    TempData["message"] = "Hesabınız Onaylandı";
                    return RedirectToAction("Login", "Account");
                }
            }
            TempData["message"] = "Kullanıcı bulunamadı !";
            return View();

        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }


        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string mail)
        {
            if (string.IsNullOrEmpty(mail))
            {
                TempData["message"] = "Eposta adersinizi giriniz!";

                return View(mail);
            }
            var user = await _userManager.FindByEmailAsync(mail);
            if (user == null)
            {
                TempData["message"] = "Girdiğiniz Eposta adresi ile kayıtlı kullanıcı yok!";
                return View();

            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var url = Url.Action("ResetPassword", "Account", new { user.Id, token });
            try
            {
                await _emailSender.SendEmailAsync(mail, "Parola Sıfırlama", $"Parolanızı yenilemek için linke <a href='http://localhost:5019{url}'>tıklayınız</a>.");
                TempData["message"] = "E-posta adresinize gönderilen link ile şifrenizi sıfırlayabilirsiniz.";
            }
            catch (Exception ex)
            {
                TempData["error"] = $"E-posta gönderimi sırasında bir hata oluştu: {ex.Message}";
                return View();
            }
            return View();
        }

        public IActionResult ResetPassword(string Id, string token)
        {
            if (Id == null || token == null)
            {
                return RedirectToAction("Login");
            }
            var model = new ResetPasswordModel { Token = token };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    TempData["message"] = "Girdiğiniz Eposta adresi ile kayıtlı kullanıcı yok!";
                    return RedirectToAction("Login");
                }
                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                if (result.Succeeded)
                {
                    TempData["message"] = "Şifreniz başarıyla değiştirilmiştir!";

                    return RedirectToAction("Login");
                }

                foreach (IdentityError err in result.Errors)
                {
                    ModelState.AddModelError("", err.Description);
                }
            }
            return View(model);
        }


    }
}