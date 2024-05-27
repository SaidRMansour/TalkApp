# Secure Software Development Project: Secure Messaging Application
![.NET](https://img.shields.io/badge/.NET-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![C%23](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Google](https://img.shields.io/badge/Google-4285F4?style=for-the-badge&logo=google&logoColor=white)
![OAuth2](https://img.shields.io/badge/OAuth2-3A3A3A?style=for-the-badge&logo=oauth&logoColor=white)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)

## Project Overview

This project is a secure messaging application designed to provide robust end-to-end encryption and federated authentication using Google OAuth. The primary objective is to protect users' personal information and ensure secure communication by leveraging advanced encryption techniques and secure authentication methods.

## Features

### End-to-End Encryption

- **Encryption and Decryption**: All messages are encrypted on the server before being sent to the recipient and decrypted only when the recipient opens the message. Messages are also decrypted for the sender to display a thread of chats, simplifying the user interface.
- **Diffie-Hellman and AES**: Diffie-Hellman algorithm is used for key exchange, ensuring strong encryption, while AES is used for the actual message encryption, providing robust data protection.

### Federated Authentication

- **Google OAuth Integration**: Users can log in using their existing Google accounts, simplifying access without compromising security. This minimizes the need for creating and remembering new passwords while leveraging the security of well-established authentication services.

### User-Friendly Interface

- **Intuitive Design**: The application features a responsive and easy-to-navigate interface, allowing users to start new conversations and manage existing ones effortlessly. The design focuses on simplicity and efficiency, making it accessible to users with varying technical skills.

## Technology Stack

- **.NET 8**
- **ASP.NET Core**
- **Entity Framework Core**
- **SQLite**
- **Google OAuth**
- **C#**
- **HTML5**
- **CSS3**
- **JavaScript**

## Setup and Installation

### Prerequisites

- **.NET SDK 8.0.5**
- **Any IDE that supports .NET development (e.g., Visual Studio, VS Code)**

### Running the Application

1. **Clone the repository**:
   ```sh
   git clone <repository_url>
   cd <repository_directory>
   ```
2. **Configure environment variables**:
   Create a .env file in the root of the project and add the following:
   ```sh
   GOOGLE_CLIENT_ID=<your_google_client_id>
   GOOGLE_CLIENT_SECRET=<your_google_client_secret>
   ```
3. Install dependencies:
   ```sh
   dotnet restore
   ```

4. Update the database:
   ```sh
   dotnet ef database update
   ```

5. Run the application:
   ```sh
   dotnet run
   ```

6. Open the application:
Open a web browser and navigate to http://localhost:7251/ to access the application.

## Usage

1. Login:
   Click on the login link to authenticate using Google OAuth.

2. Send Messages:
   After authentication, users can send encrypted messages to other registered users.

3. View Messages:
   Users can view their chat threads with other users, with messages being decrypted securely.

## Security Measures
* HTTPS Communication: Ensure all communication with the server is over HTTPS in production environments.
* Secure Storage: Store sensitive information such as client secrets securely using environment variables or secure vault solutions.
* IDataProtectionProvider: Private keys are secured using IDataProtectionProvider, which ensures that even if the database is compromised, the AES key required for decryption remains protected.

## Documentation
- API Documentation: Detailed API documentation for Google OAuth can be found **[here](https://developers.google.com/identity/protocols/oauth2)**.
- OAuth 2.0 Documentation: For more information on implementing OAuth 2.0 and OpenID Connect, refer to the official **[OAuth 2.0 documentation](https://oauth.net/2/)**.

## Contributing
* Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.

## License
* This project is open-source and available under the MIT License.
