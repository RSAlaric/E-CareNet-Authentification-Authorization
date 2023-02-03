using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_CareNet.Models
{
    public class TowFactorAuthenticationViewModel
    {
        //on va utiliser pour le Login
        public string Code { get; set; }
        
        //on va utiliser pour inscription et signup
        public string Token { get; set; }
        public string QRCodeUrl { get; set; }
    }
}
