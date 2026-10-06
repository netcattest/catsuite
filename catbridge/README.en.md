# CatBridge

[Português brasileiro](README.md)

## Download and run

[Windows ZIP](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-windows-amd64.zip) · [Linux TAR.GZ](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-linux-amd64.tar.gz) · [SHA-256](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/SHA256SUMS.txt)

Download the package for your system, extract all files and open a terminal in the extracted folder. The executable is named `catbridge.exe` on Windows and `catbridge` on Linux. Ready-to-run packages do not require Go. Follow the pairing instructions below.

Connect CatSuite to approved tools on your computer through typed capabilities, signed communication and traceable results.

## Build

Go 1.26 or newer is required.

```powershell
go build -buildvcs=false -trimpath -ldflags="-s -w" -o catbridge.exe .
```

On Linux, use `-o catbridge`. No account or hosted service is required.

## Pair

Choose your computer’s local address, reachable from the phone:

```powershell
.\catbridge.exe serve -state .\private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743
```

The terminal displays an address and a 24-digit code in six groups. Enable the extension module in CatSuite Settings → Extensions. Open Extensions → Connections → Pair CatBridge and enter the address and code. Spaces are accepted. No QR is needed.

The code expires after two minutes and pairs one device. The app authenticates the server identity before sending the code through the authenticated HTTPS channel. Codes are not retained with installed connections. Incorrect codes cannot install a connection.

Generate another code from another terminal, using the same state and address:

```powershell
.\catbridge.exe pair -state .\private-state -public https://192.168.1.20:8743 -lang en
```

For the standard Android emulator on the same computer:

```powershell
.\catbridge.exe serve -state .\private-emulator -listen 127.0.0.1:8743 -public https://10.0.2.2:8743 -lang en
```

Keep the public hostname consistent. The server certificate includes it. For a new hostname, choose a fresh state directory and pair again. Configure network access to the chosen port; CatBridge does not change firewall settings.

## Executors

The Bridge can pair and return its capability catalog without tools installed. Unavailable tools remain unavailable. Nuclei uses a local executable and reviewed HTTP templates. httpx, Katana and Schemathesis use approved Linux containers and a controlled network broker. Additional SDK 1.4 adapters require their respective images, hashes and authorization.

```powershell
.\catbridge.exe serve -state .\private-state -listen 0.0.0.0:8743 -public https://192.168.1.20:8743 -scope https://api.example.test -nuclei C:\Tools\nuclei.exe -templates .\examples\templates.json -lang en
```

Set the template path and SHA-256 in the example manifest to your reviewed file. Aurora is a fictional laboratory example.

Prepare the three priority Linux executors with Docker Linux engine, Python 3.12+ and `cryptography`:

```sh
python runtime/prepare.py --output runtime/prepared --go go --docker docker
```

Start with `-tool-lock runtime/prepared/tools.lock.json -tool-key AUTHOR_FINGERPRINT`, using `runtime/prepared/author.sha256`. Preparation and updates are host administrative operations. Plugins cannot choose arbitrary executables, shell commands or images.

## Revoke

```powershell
.\catbridge.exe revoke -state .\private-state -public https://192.168.1.20:8743 -device DEVICE_ID
```

Removing a connection in the app revokes its certificate when the Bridge is reachable and deletes its local key. Use host revocation for an offline device.

Compatible with CatSuite 1.3.7+100 including numeric pairing, SDK 1.4 and CatBridge Protocol 2. Existing Protocol 2 connections remain compatible. Existing signed pairing data are still accepted; new Bridge codes are numeric. Protocol 1 is rejected.

Keep the state directory, keys, certificates, codes and logs private. Restrict server access to the required network. Dependency notices remain in `THIRD_PARTY_LICENSES.txt`.

## Downloads

[Windows 64-bit](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-windows-amd64.zip) · [Linux 64-bit](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/catbridge-linux-amd64.tar.gz) · [SHA-256](https://github.com/netcattest/catsuite/releases/download/tools-1.2.0/SHA256SUMS.txt)

[SDK](../catsuite-vscode/sdk/catsuite.d.ts)
