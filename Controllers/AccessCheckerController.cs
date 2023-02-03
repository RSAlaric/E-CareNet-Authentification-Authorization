using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_CareNet.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {

        //Accessible par tous, même si les utilisateurs ne sont pas connectés
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

        //Accessible par les utilisateurs connectés
        [Authorize]
        public IActionResult AuthorizedAccess()
        {
            return View();
        }
        //Accessible par les utilisateurs qui ont un rôle d'utilisateur
        [Authorize(Roles ="User")]
        public IActionResult UserAccess()
        {
            return View();
        }
        //Accessible par les utilisateurs qui ont un rôle d'utilisateur et admin
        [Authorize(Roles = "User,Admin")]
        public IActionResult UserORAdminAccess()
        {
            return View();
        }
        [Authorize(Policy = "UserAndAdmin")]
        public IActionResult UserANDAdminAccess()
        {
            return View();
        }
        //Accessible par les utilisateurs qui ont un rôle d'administrateur
        [Authorize(Policy = "Admin")]
        public IActionResult AdminAccess()
        {
            return View();
        }
        //Accessible par les utilisateurs administrateurs avec une demande de création pour être vrai
        //Accessible by Admin users with a claim of create to be True
        [Authorize(Policy = "Admin_CreateAccess")]
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }
        //Accessible par les utilisateurs administrateurs avec une demande de création, de modification et de suppression (ET NON OU)
        //Accessible by Admin users with a claim of Create, Edit and Delete (AND NOT OR)
        [Authorize(Policy = "Admin_Create_Edit_DeleteAccess")]
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }
        //Accessible by Admin user with Create, Edit and Delete(AND NOT OR), or if the user role is superAdmin
        //Accessible par l'utilisateur Admin avec Créer, Modifier et Supprimer(ET NON OU), ou si le rôle d'utilisateur est superAdmin
        [Authorize(Policy = "Admin_Create_Edit_DeleteAccess_OR_SuperAdmin")]
        public IActionResult Admin_Create_Edit_DeleteAccess_OR_SuperAdmin()
        {
            return View();
        }
    }
}
