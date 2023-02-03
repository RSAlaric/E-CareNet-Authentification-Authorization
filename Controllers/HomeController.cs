using E_CareNet.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Localization;

namespace E_CareNet.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IHtmlLocalizer<HomeController> _localizer;
        private readonly UserManager<IdentityUser> _userManager;

        public HomeController(ILogger<HomeController> logger, IHtmlLocalizer<HomeController> localizer, UserManager<IdentityUser> userManager)
        {
            _logger = logger;
            _localizer = localizer;
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if(user == null)
            {
                ViewData["TwoFactorEnabled"] = false;
            }
            else
            {
                ViewData["TwoFactorEnabled"] = user.TwoFactorEnabled;
            }
            
            return View();
        }
        

        [Authorize(Roles ="Admin")]
        public IActionResult Privacy()
        {
            return View();
        }
        public IActionResult AccessDenied()
        {
            return View();
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
