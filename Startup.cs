using E_CareNet.Data;
using E_CareNet.Models;
using E_CareNet.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using E_CareNet.Authorize;

namespace E_CareNet
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("DefaulltConnection")));
            services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders().AddDefaultUI();
            services.AddTransient<IEmailSender, MailJetEmailSender>();
            services.Configure<IdentityOptions>(opt =>
            {
                opt.Password.RequiredLength = 5;
                opt.Password.RequireLowercase = true;
                opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(30);
                opt.Lockout.MaxFailedAccessAttempts = 5;
            });
            //services.ConfigureApplicationCookie(opt =>
            //{
            //   opt.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Home/AccessDenied");
            //});
            services.AddAuthentication().AddFacebook(options =>
            {
                options.AppId = "5682032668502161";
                options.AppSecret = "e6647b47f1c0c8cd140f3e6ab828bfbe";
            });

            services.AddLocalization(option => option.ResourcesPath = "Resources");
            services.Configure<RequestLocalizationOptions>(option =>
            {
                var cultures = new List<CultureInfo> {
                new CultureInfo("en-US"),
                new CultureInfo("fr-FR")
                };
                option.DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture(culture:"fr-FR", uiCulture: "fr-FR");
                option.SupportedCultures = cultures;
                option.SupportedUICultures = cultures;
            });
            services.AddMvc()
                .AddViewLocalization(Microsoft.AspNetCore.Mvc.Razor.LanguageViewLocationExpanderFormat.Suffix)
                .AddDataAnnotationsLocalization();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
                options.AddPolicy("UserAndAdmin", policy => policy.RequireRole("Admin").RequireRole("User"));
                options.AddPolicy("Admin_CreateAccess", policy => policy.RequireRole("Admin").RequireClaim("Create", "True"));
                options.AddPolicy("Admin_Create_Edit_DeleteAccess", policy => policy.RequireRole("Admin").RequireClaim("Create", "True")
                .RequireClaim("Edit", "True")
                .RequireClaim("Delete", "True"));

                options.AddPolicy("Admin_Create_Edit_DeleteAccess_OR_SuperAdmin", policy => policy.RequireAssertion(context =>
                AuthorizeAdminWithClaimsOrSuperAdmin(context)));

                options.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
            });

            services.AddControllersWithViews();
            services.AddRazorPages();

            
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRequestLocalization(app.ApplicationServices.GetRequiredService<IOptions<RequestLocalizationOptions>>().Value);
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
         
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
        private bool AuthorizeAdminWithClaimsOrSuperAdmin(AuthorizationHandlerContext context)
        {
            return (context.User.IsInRole("Admin") && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
                    ) || context.User.IsInRole("SuperAdmin");
        }
    }
}
