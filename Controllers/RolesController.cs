using E_CareNet.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_CareNet.Controllers
{
    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _roleManager = roleManager;
            _userManager = userManager;
        }
        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();
            return View(roles);
        }
        [HttpGet]
        public IActionResult Upsert(string id)
        {
            if (String.IsNullOrEmpty(id)) 
            {
                return View();
            }
            else
            {
                //update
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == id);
                return View(objFromDb);
            }
             
        }
        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
           if(await _roleManager.RoleExistsAsync(roleObj.Name))
            {
                //error
                TempData[SD.Error] = "Le rôle existe déjà.";
                
            }
           if(string.IsNullOrEmpty(roleObj.Id))
            {
                //create
                await _roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
                TempData[SD.Success] = "Rôle créé avec succès.";
            }
           else
            {
                //update
                var objRoleFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleObj.Id);
                if (objRoleFromDb == null)
                {
                    TempData[SD.Error] = "Rôle introuvable.";
                    return RedirectToAction(nameof(Index));
                }
                objRoleFromDb.Name = roleObj.Name;
                objRoleFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(objRoleFromDb);
                TempData[SD.Success] = "Rôle mis à jour avec succès.";
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")] 
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null)
            {
                TempData[SD.Error] = "Rôle introuvable";
                return RedirectToAction(nameof(Index));
            }
            var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == id).Count();
            if (userRolesForThisRole > 0)
            {
                TempData[SD.Error] = "Impossible de supprimer ce rôle, car des utilisateurs sont affectés à ce rôle.";
                return RedirectToAction(nameof(Index));
            }
            await _roleManager.DeleteAsync(objFromDb);
            TempData[SD.Success] = "Rôle supprimé avec succès";
            return RedirectToAction(nameof(Index));
        }
    }
}
