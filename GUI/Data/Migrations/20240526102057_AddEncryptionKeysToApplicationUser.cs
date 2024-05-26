using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GUI.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEncryptionKeysToApplicationUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "EncryptedPrivateKey",
                table: "AspNetUsers",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "EncryptionKey",
                table: "AspNetUsers",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedPrivateKey",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "EncryptionKey",
                table: "AspNetUsers");
        }
    }
}
