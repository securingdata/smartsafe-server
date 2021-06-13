# SmartSafe Server

The SmartSafe project aims at providing a solution to securely store your passwords.
This password manager is split in several repositories: see the corresponding repository to have a complete description of each one.

The SmartSafe Server part consists in a Java Card application that securely store data. Access in write and read mode are protected by a user password.

## Security assumptions

The use of a Java Card smart card brings strong security elements.

The loading of an application is controlled by a user key and only code signed by Securing Data key can be loaded. An attacker cannot load a malicious application that could successfully dump the data owned by the SmartSafe server application.

The overall attack area is limited to the Card Manager (that is supposed to have been evaluated) and the commands of the SmartSafe server application. Two types of attack can be considered : physical attacks and logical attacks.

Concerning physical attacks (fault injection and side channel attacks), the use of a certified Java Card smart card mitigates these attack paths. Therefore, no specific countermeasures are added in the implementation in order to counteract these kinds of attack.

Concerning logical attacks, a specific attention has been taken in order to implement in a safe way logical accesses to the data protected by the application. See the JavaDoc of the application for more details on this aspect.

## Quick start

The server part is intended to be loaded on a Java Card smart card. Use the standard Java Card SDK provided by Oracle.

The package is intended to be compiled with AID: "53 6D 61 72 74 53 61 66 65" (SmartSafe).
The applet should have the following AID: "53 6D 61 72 74 53 61 66 65 41 70 70" (SmartSafeApp).

Concerning loading, both package and applet should be loaded under supplementary security domain with AID: "53 65 63 75 72 69 6E 67 44 61 74 61 55 73 65 72" (SecuringDataUser) in order to be fully compatible with SmartSafe Client.

## Hardware set-up
This part is detailed in SmartSafe Client project.

## Road map
The following features are already developed:

 - Protection of user commands by a password
 - Ability to create groups that contain entries that contain all the needed data for a password manager
 - Ability to read/write data in groups and entries
 - Secure messaging between the Client and the Server in order to avoid Man-in-the-middle and replay attacks
 - Editing Group name and other stuff

The following features are intended to be developed:

 - FIDO2 support
 - To be announced...
