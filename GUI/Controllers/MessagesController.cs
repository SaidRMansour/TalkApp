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
            var currentUser = await _userManager.GetUserAsync(User);
            users.Remove(currentUser);

            var model = new SendMessageViewModel
            {
                Users = users,

                // Tilføjer sidste sendte besked
                RecentMessage = await GetRecentMessageAsync(currentUser.Id)
            };

            return View(model);
        }

        private async Task<RecentMessageViewModel> GetRecentMessageAsync(string userId)
        {
            var recentMessage = await _context.Messages
                .Where(m => m.SenderId == userId || m.ReceiverId == userId)
                .OrderByDescending(m => m.Timestamp)
                .FirstOrDefaultAsync();

            if (recentMessage != null)
            {
                var otherUserId = recentMessage.SenderId == userId ? recentMessage.ReceiverId : recentMessage.SenderId;
                var otherUser = await _userManager.FindByIdAsync(otherUserId);

                return new RecentMessageViewModel
                {
                    SenderName = otherUser.UserName,
                    Timestamp = recentMessage.Timestamp.ToString("HH:mm"),
                    UserId = otherUser.Id
                };
            }

            return null;
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendMessage(string receiverId, string message)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var sender = await _userManager.GetUserAsync(User);
                    var receiver = await _userManager.FindByIdAsync(receiverId);

                    if (sender == null || receiver == null)
                    {
                        ModelState.AddModelError(string.Empty, "Afsender eller modtager ikke fundet.");
                        return RedirectToAction(nameof(Thread), new { userId = receiverId });
                    }

                    var encryptionService = new EncryptionService(_dataProtectionProvider, sender.PrivateKey);
                    var receiverPublicKey = GetPublicKey(receiver.Id);
                    encryptionService.GenerateSharedKey(receiverPublicKey);

                    var encryptedMessage = encryptionService.EncryptMessage(message);

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
                    return RedirectToAction(nameof(Thread), new { userId = receiverId });
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError(string.Empty, $"Der opstod en fejl under afsendelse af beskeden: {ex.Message}");
                }
            }

            return RedirectToAction(nameof(Thread), new { userId = receiverId });
        }


        // GET: Messages/Thread/{userId}
        public async Task<IActionResult> Thread(string userId)
        {
            var currentUserId = _userManager.GetUserId(User);
            var messages = await _context.Messages
                .Where(m => (m.SenderId == currentUserId && m.ReceiverId == userId) ||
                            (m.SenderId == userId && m.ReceiverId == currentUserId))
                .OrderBy(m => m.Timestamp)
                .ToListAsync();

            var decryptedMessages = new List<DecryptedMessageViewModel>();
            foreach (var message in messages)
            {
                bool isMe = message.SenderId == currentUserId;

                var encryptionService = new EncryptionService(_dataProtectionProvider, GetProtectedPrivateKey(currentUserId));

                if (message.SenderId == currentUserId)
                {
                    // Dekrypter beskeder sendt af den nuværende bruger
                    encryptionService.GenerateSharedKey(GetPublicKey(userId));
                }
                else
                {
                    // Dekrypter beskeder modtaget fra den anden bruger
                    encryptionService.GenerateSharedKey(GetPublicKey(message.SenderId));
                }

                var sender = await _userManager.FindByIdAsync(message.SenderId);
                if (encryptionService.VerifyHMAC(message.EncryptedMessage, message.HMAC, message.IV))
                {
                    var decryptedMessage = encryptionService.DecryptMessage(message.EncryptedMessage, message.IV, message.HMAC);
                    decryptedMessages.Add(new DecryptedMessageViewModel
                    {
                        // Vis mine egne beskeder som "Me" i stedet for brugernavn
                        SenderName = isMe ? "Mig" : sender.UserName, 
                        Content = decryptedMessage,
                        Timestamp = message.Timestamp.ToString("HH:mm")
                    });
                    
                }
                else
                {
                    decryptedMessages.Add(new DecryptedMessageViewModel
                    {
                        SenderName = isMe ? "Mig" : sender.UserName,
                        Content = "HMAC validering fejlet.",
                        Timestamp = message.Timestamp.ToString("HH:mm")

                    });
                }
            }

            var model = new ChatThreadViewModel
            {
                Messages = decryptedMessages,
                ReceiverId = userId,
                ReceiverName = (await _userManager.FindByIdAsync(userId)).UserName
            };

            return View(model);
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

    
}
