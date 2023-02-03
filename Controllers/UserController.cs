using E_CareNet.Data;
using E_CareNet.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace E_CareNet.Controllers
{
    
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }
        [Authorize]
        public IActionResult Index()
        {
            var userList = _db.ApplicationUsers.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach(var user in userList)
            {
                var role = userRole.FirstOrDefault(u => u.UserId == user.Id);
                if(role == null)
                {
                    user.Role = "Aucun";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId).Name;
                }
            }
            return View(userList);
        }
        [Authorize(Policy = "Admin")]
        public IActionResult Edit(string userId)
        {
            var objFromDb = _db.ApplicationUsers.FirstOrDefault(u =>u.Id==userId);
            if(objFromDb==null)
            {
                return NotFound();
            }
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            var role = userRole.FirstOrDefault(u => u.UserId == objFromDb.Id);
            if(role !=null)
            {
                objFromDb.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId).Id;
            }
            objFromDb.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            { 
                Text = u.Name,
                Value = u.Id
            
            });
            return View(objFromDb);
        }

        [HttpPost]
        [Authorize(Policy = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if (ModelState.IsValid) 
            { 
                var objFromDb = _db.ApplicationUsers.FirstOrDefault(u => u.Id == user.Id);
                if (objFromDb == null)
                {
                    return NotFound();
                }
                var userRole = _db.UserRoles.FirstOrDefault(u => u.UserId == objFromDb.Id);
                if(userRole != null)
                {
                    var previousRoleName = _db.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
                    //effacer l'ancienne rôle
                    await _userManager.RemoveFromRoleAsync(objFromDb, previousRoleName);
                
                }
                    //ajouter nouveau role
                    await _userManager.AddToRoleAsync(objFromDb, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
                    objFromDb.Name = user.Name;
                    _db.SaveChanges();
                    TempData[SD.Success] = "L'utilisateur a été modifié avec succès.";
                return RedirectToAction(nameof(Index));

            }


            user.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id

            });
            return View(user);
        }
        
        [HttpPost]
        [Authorize(Policy = "Admin")]
        public IActionResult LockUnlock(string userId)
        {
            var objFromDb = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if(objFromDb == null)
            {
                return NotFound();
            }
            if(objFromDb.LockoutEnd!=null && objFromDb.LockoutEnd > DateTime.Now)
            {
                //L'utilisateur est verrouillé et le restera jusqu'à la fin du verrouillage(User is locked and will remain locked untill lockoutend time)
                //Cliquer sur cette action les débloquera(Clicking on this action will unlock them)
                objFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "Utilisateur a été déverrouillé avec succès.";
            }
            else
            {
                //L'utilisateur n'est pas verrouillé et nous voulons verrouiller l'utilisateur
                objFromDb.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "Utilisateur a été verrouillé avec succès";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [Authorize(Policy = "Admin_Create_Edit_DeleteAccess_OR_SuperAdmin")]
        public IActionResult Delete(string userId)
        {
            var objFromDb = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }
            _db.ApplicationUsers.Remove(objFromDb);
            _db.SaveChanges();
            TempData[SD.Success] = "Utilisateur a été supprimé avec succès";
            return RedirectToAction(nameof(Index));
        }
        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var existingUserClaims = await _userManager.GetClaimsAsync(user);

            var model = new UserClaimsViewModel()
            {
                UserId = userId
            };

            foreach(Claim claim in ClaimStore.claimsList)
            {
                UserClaim userClaim = new UserClaim
                {
                    ClaimType = claim.Type
                };
                if (existingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.Claims.Add(userClaim);
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel userClaimsViewModel)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userClaimsViewModel.UserId);

            if (user == null)
            {
                return NotFound();
            }

            var claims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, claims);

            if(!result.Succeeded)
            {
                TempData[SD.Error] = "Erreur lors de la suppression de l'Action";
                return View(userClaimsViewModel);
            }

           result = await _userManager.AddClaimsAsync(
            user, userClaimsViewModel.Claims.Where(c => c.IsSelected).Select(c => new Claim(c.ClaimType, c.IsSelected.ToString()))
                );
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Erreur lors de l'ajout de l'Action";
                return View(userClaimsViewModel);
            }
            TempData[SD.Success] = "La mise a jour de l'action d'utilisateur réussies";
            return RedirectToAction(nameof(Index));
            
        }
    }
}