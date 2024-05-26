using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GUI.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPrivateKeyToApplicationUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedPrivateKey",
                table: "AspNetUsers");

            migrationBuilder.RenameColumn(
                name: "EncryptionKey",
                table: "AspNetUsers",
                newName: "PrivateKey");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "PrivateKey",
                table: "AspNetUsers",
                newName: "EncryptionKey");

            migrationBuilder.AddColumn<string>(
                name: "EncryptedPrivateKey",
                table: "AspNetUsers",
                type: "TEXT",
                nullable: false,
                defaultValue: "");
        }
    }
}
