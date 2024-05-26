using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using GUI.Data;
using GUI.Models;
using GUI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace GUI.Controllers
{
    [Authorize]
    public class MessagesController : Controller
    {
        private readonly ILogger<MessagesController> _logger;
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtectionProvider _dataProtectionProvider;

        public MessagesController(ILogger<MessagesController> logger, ApplicationDbContext context, UserManager<ApplicationUser> userManager, IDataProtectionProvider provider)
        {
            _logger = logger;
            _context = context;
            _userManager = userManager;
            _dataProtectionProvider = provider;
        }

        // GET: Messages/Send
        public async Task<IActionResult> Send()
        {
            var users = await _userManager.Users.ToListAsync();
            users.Remove(await _userManager.GetUserAsync(User));
            var model = new SendMessageViewModel
            {
                Users = users
            };
            return View(model);
        }

        // POST: Messages/Send
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Send(SendMessageViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var sender = await _userManager.GetUserAsync(User);
                    var receiver = await _userManager.FindByIdAsync(model.ReceiverId);

                    if (sender == null || receiver == null)
                    {
                        ModelState.AddModelError(string.Empty, "Afsender eller modtager ikke fundet.");
                        model.Users = await _userManager.Users.ToListAsync();
                        model.Users.Remove(sender);
                        return View(model);
                    }

                    var encryptionService = new EncryptionService(_dataProtectionProvider, sender.PrivateKey);
                    var receiverPublicKey = GetPublicKey(receiver.Id);
                    encryptionService.GenerateSharedKey(receiverPublicKey);

                    var encryptedMessage = encryptionService.EncryptMessage(model.Message);

                    var newMessage = new Message
                    {
                        SenderId = sender.Id,
                        ReceiverId = receiver.Id,
                        EncryptedMessage = encryptedMessage,
                        IV = encryptionService.GetIV(),
                        HMAC = encryptionService.GetHMAC(),
                        Timestamp = DateTime.Now
                    };

                    _context.Messages.Add(newMessage);
                    await _context.SaveChangesAsync();

                    TempData["SuccessMessage"] = "Beskeden er sendt med succes.";
                    return RedirectToAction(nameof(Receive));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError(string.Empty, $"Der opstod en fejl under afsendelse af beskeden: {ex.Message}");
                }
            }

            model.Users = await _userManager.Users.ToListAsync();
            model.Users.Remove(await _userManager.GetUserAsync(User)); // Re-add the list of users
            return View(model);
        }

        // GET: Messages/Receive
        public async Task<IActionResult> Receive()
        {
            try
            {
                var userId = _userManager.GetUserId(User);
                var messages = await _context.Messages
                    .Where(m => m.ReceiverId == userId)
                    .ToListAsync();

                var decryptedMessages = new List<DecryptedMessageViewModel>();

                foreach (var message in messages)
                {
                    var senderPublicKey = GetPublicKey(message.SenderId);
                    var encryptionService = new EncryptionService(_dataProtectionProvider, GetProtectedPrivateKey(userId));
                    encryptionService.GenerateSharedKey(senderPublicKey);
                    var sender = await _userManager.FindByIdAsync(message.SenderId);

                    if (encryptionService.VerifyHMAC(message.EncryptedMessage, message.HMAC, message.IV))
                    {
                        var decryptedMessage = encryptionService.DecryptMessage(message.EncryptedMessage, message.IV, message.HMAC);
                        decryptedMessages.Add(new DecryptedMessageViewModel
                        {
                            SenderName = sender.UserName,
                            Content = decryptedMessage
                        });
                    }
                    else
                    {
                        decryptedMessages.Add(new DecryptedMessageViewModel
                        {
                            SenderName = sender.UserName,
                            Content = "HMAC validering fejlet."
                        });
                    }
                }

                return View(decryptedMessages);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, $"Der opstod en fejl under modtagelse af beskeden: {ex.Message}");
                return View(new List<DecryptedMessageViewModel>());
            }
        }

        private byte[] GetPublicKey(string userId)
        {
            var user = _context.Users.Find(userId);
            if (user == null || string.IsNullOrEmpty(user.PublicKey))
            {
                throw new InvalidOperationException("User or public key not found.");
            }
            return Convert.FromBase64String(user.PublicKey);
        }

        private string GetProtectedPrivateKey(string userId)
        {
            var user = _context.Users.Find(userId);
            if (user == null || string.IsNullOrEmpty(user.PrivateKey))
            {
                throw new InvalidOperationException("User or private key not found.");
            }
            return user.PrivateKey;
        }
    }

    public class DecryptedMessageViewModel
    {
        public string SenderId { get; set; }
        public string Content { get; set; }
        public string SenderName { get; set; }
    }
}
