using System;
namespace GUI.Models
{
    public class Message
    {
        public int Id { get; set; }
        public string SenderId { get; set; }
        public string ReceiverId { get; set; }
        public byte[] EncryptedMessage { get; set; }
        public byte[] IV { get; set; }
        public byte[] HMAC { get; set; }
        public DateTime Timestamp { get; set; }
    }

}

