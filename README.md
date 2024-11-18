# Authz Program

This program retrieves security group memberships for a specified user in the current domain. If no argument is provided, it outputs the group memberships for the domain administrator account (RID 500).

## Features

- **Automatic Domain Detection**: Automatically identifies the current domain.
- **Default to Domain Administrator**: Uses the domain administrator's SID if no argument is provided.
- **Group Membership Retrieval**: Displays the security groups associated with the specified user.

## Requirements

- **Operating System**: Windows
- **.NET Framework**: 4.7.2 or higher
- **Dependencies**:
  - [Vanara.PInvoke](https://github.com/dahall/Vanara) library
  - `System.DirectoryServices` namespace

## Installation and Usage

1. **Build the Project**: Compile the code using your preferred .NET development environment.
2. **Run the Program**:
   - Without arguments (uses domain administrator SID):

     ```bash
     Authz.exe
     ```

   - With a specified SID:

     ```bash
     Authz.exe S-1-5-21-XXXXX-XXXXX-XXXXX-500
     ```

## Notes

- Ensure you have the necessary permissions to access domain information.
- The program utilizes the `Vanara.PInvoke` library for Windows API interactions.

## License

This project is licensed under the MIT License.
