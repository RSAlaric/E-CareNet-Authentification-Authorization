using E_CareNet.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace E_CareNet.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager; 
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;
        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender, 
            UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _signInManager = signInManager;
            _urlEncoder = urlEncoder;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            return View();
        }
        /////////////////////////CONTROLLEUR DE VUE D'INSCRIPTION/////////////////////////
        
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Register(string returnurl=null)
        {
            if(!await _roleManager.RoleExistsAsync("Admin"))
            {
                //creer un rôle
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }

            List<SelectListItem> listItems = new List<SelectListItem>();
            listItems.Add(new SelectListItem()
            {
                Value = "Admin",
                Text = "Admin"

            });
            listItems.Add(new SelectListItem()
            {
                Value = "User",
                Text = "User"

            });
            ViewData["ReturnUrl"] = returnurl;
            RegisterViewModel registerViewModel = new RegisterViewModel() {
                RoleList = listItems
            };
            return View(registerViewModel);
        }

        //CONTROLLEUR D'INSCRIPTION
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnurl=null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    if(model.RoleSelected!=null && model.RoleSelected.Length>0 && model.RoleSelected == "Admin")
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackurl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

                    await _emailSender.SendEmailAsync(model.Email, "Confirmer votre Compte - E-CareNet",
                        "Veuillez votre Compte en cliquant ici: <a href=\"" + callbackurl + "\">liens</a>");
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);
                
                }
                AddErrors(result);
            }
            List<SelectListItem> listItems = new List<SelectListItem>();
            listItems.Add(new SelectListItem()
            {
                Value = "Admin",
                Text = "Admin"

            });
            listItems.Add(new SelectListItem()
            {
                Value = "User",
                Text = "User"

            });
            model.RoleList = listItems;
            return View(model);
        }

        //ACTION POUR CONFIRMATION DE CREER LE COMPTE par email
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId,string code)
        {
            if(userId==null || code==null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("Error");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }


        //CONTROLLEUR DE VUE CONNEXION
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnurl=null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }

        /////////////////////////CONTROLLEUR DE CONNEXION/////////////////////////
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnurl=null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    return LocalRedirect(returnurl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnurl, model.RememberMe});
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Tentative de connexion invalide.");
                    return View(model);
                }
               
            }

            return View(model);
        }




        /////////////////////////CONTROLLEUR DE MOT DE PASSSE OUBLIER/////////////////////////
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Réinitialiser le Mot de Passe - E-CareNet",
                    "Veuillez réinitialiser votre mot de passe en cliquant ici: <a href=\"" + callbackurl + "\">liens</a>");

                return RedirectToAction("ForgotPasswordConfirmation");
            }
            return View(model);
        }

    
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        /////////////////////////CONTROLLEUR DE MOT DE PASSSE POUR ACTIVER LIENS ENVOYER PAR L'ADRESSE EMAIL/////////////////////////
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code=null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }

                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if(result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }
                AddErrors(result);
            }
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        /////////////////////////CONTROLLEUR DE CONNEXION FACEBOOK/////////////////////////

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnurl = null)
        {
            //request a redirect to the external login provider
            var redirecturl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnurl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirecturl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnurl = null, string remoteError = null)
        {
            if(remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if(info==null)
            {
                return RedirectToAction(nameof(Login));
            }
            //connexion d'utilisateur avec cet external login provider, si l'user ont deja le login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if(result.Succeeded)
            {
                //update any authentication tokens
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnurl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction("VerifyAuthenticatorCode", new { returnurl = returnurl });
            }
            else
            {
                //si l'User n'ont pas de compte, donc on doit lui creer un compte
                ViewData["ReturnUrl"] = returnurl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);
                return View("ExternalLoginConfirmation", new ExternalloginConfirmationViewModel { Email = email, Name=name });
    
            }
            
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalloginConfirmationViewModel model, string returnurl = null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if(ModelState.IsValid)
            {
                //get the info about the user from external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("Error");
                }
                var user = new ApplicationUser {  UserName = model.Email, Email = model.Email, Name = model.Name };
                var result = await _userManager.CreateAsync(user);
                if(result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                    result = await _userManager.AddLoginAsync(user, info);
                    if(result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                        return LocalRedirect(returnurl);
                    }
                }
                AddErrors(result);
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(model);
        }
        /// <summary>
        ///FIN LOGIN FACEBOOK
        /// </summary>
        /// <returns></returns>
        /////////////////////////CONTROLLEUR DE DECONNEXION/////////////////////////

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }


        /////////////////////////CONTROLLEUR QR CODE CONNEXION/////////////////////////
        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {
            
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index),"Home");
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            string AuthenticatorUri = string.Format(AuthenticatorUriFormat,_urlEncoder.Encode("E-CareNet"),
                _urlEncoder.Encode(user.Email), token);
            var model = new TowFactorAuthenticationViewModel() { Token = token,QRCodeUrl=AuthenticatorUri };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EnableAuthenticator(TowFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verifiez", "que votre code d'authentification à deux facteurs n'a pas pu être validé");
                    return View(model);
                }
            }
            return RedirectToAction(nameof(AunthenticatorConfirmation));
        }
        [HttpGet]
        public IActionResult AunthenticatorConfirmation()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl=null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if(user == null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
        {
            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: true);
            if(result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty,"Code invalide");
                return View(model);
            }
        }





        /////////////////////////CONTROLLEUR D'ERREUR POUR LES CHAMP D'INSCRIPTION/////////////////////////
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
