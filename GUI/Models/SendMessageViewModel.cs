using System;
namespace GUI.Models
{
    public class SendMessageViewModel
    {
        public string ReceiverId { get; set; }
        public string Message { get; set; }
        public List<ApplicationUser> Users { get; set; } = new List<ApplicationUser>();
        public RecentMessageViewModel RecentMessage { get; set; }
    }
}

