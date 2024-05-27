using System;
using GUI.Controllers;

namespace GUI.Models
{
    public class ChatThreadViewModel
    {
        public List<DecryptedMessageViewModel> Messages { get; set; }
        public string ReceiverId { get; set; }
        public string ReceiverName { get; set; }
    }

}

