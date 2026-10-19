# AgentGate in the background on macOS

AgentGate can run as a per-user macOS LaunchAgent. It starts when you log in and remains running when you close its web window. A separate AgentGate app opens the local browser interface when you want it. The service runs on `127.0.0.1`, using the same agent credentials and operator credential as the terminal setup.

The installer creates a private, secret-free service definition in `~/Library/LaunchAgents/com.agentgate.broker.plist`. Paths point to your project, Python environment, configuration directory, and native Keychain helper. Private service output goes to `broker.stdout.log` and `broker.stderr.log` in the configuration directory. Installing the definition does not start the service.

One-time setup saves your existing AgentGate master password in your macOS login Keychain through the native setup interface. Enter it privately there. The background broker retrieves it through the native helper; it is not stored in the service definition, command-line arguments, or a permanent environment variable. macOS may request permission to access that Keychain item. Failed or unavailable unlock cannot expose saved provider credentials.

Before activating the background service, stop the existing terminal broker. Both startup paths hold the same private credential-store process lock. A second broker cannot open the same store while another instance holds the lock. The lock file remains after shutdown; its existence does not mean the broker is running.

The service starts at login and restarts unexpected exits with a 30-second throttle. Configuration errors, including a missing or incorrect saved unlock, pause startup instead of retrying indefinitely. Its private log records the error and "Background startup paused." Open **AgentGate.app**, use **Set up saved unlock…** if needed, then **Open AgentGate** to retry. A paused job remains loaded but is not running; macOS also tries it again at the next login.

A locked Keychain or another broker holding the vault lock also pauses startup. Unlock the Keychain or stop the other broker before retrying.

It starts quietly without opening browser windows on each restart. Closing the browser does not stop agents or revoke their access. To stop the service, unload the LaunchAgent; merely killing a supervised process makes macOS restart it. Uninstalling unloads the service and removes its definition, while preserving your accounts, policies, identities, and audit records. Keychain removal is a separate explicit action.

Log out stops the per-user service. Log in starts it again. The broker is unavailable while your Mac is asleep or shut down. This is local background operation, not cloud hosting or a public website. Never expose its listener through an internet proxy.

If the app cannot connect, check whether the service is loaded, whether Keychain unlock succeeded, and whether another process owns the configured port. Provider failures do not require repeated service restarts, and uncertain sends or issue creation must not be automatically retried. The installer never kills a process merely because it uses the port.

Reinstall the service definition after moving the project, replacing its Python environment, changing the configuration directory, or moving the native helper. Existing installations also need the updated definition for pause-on-error behavior; an already loaded job uses its old definition until it is unloaded and loaded again. This startup integration supports macOS only; Windows and Linux startup managers are not implemented.

Apple describes the lifecycle and plist configuration in [Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

The native app is built with the system Swift compiler and signed locally with the stable bundle identifier `com.agentgate.app`. Building or updating it does not itself read or write Keychain items or activate a service. The staged app is compiled, signed, and verified before replacing an existing installation. A locally signed app update can trigger another macOS Keychain access prompt because its code changes. Keep the private configuration directory outside the source repository.

## Build and install

The existing Gmail/GitHub setup and private credentials are reused. Developers can build the opener and install its definition with:

```sh
.venv/bin/python -m broker.mac_install --project-dir "$PWD" --config-dir "$HOME/.config/agentgate" --output "$HOME/Applications/AgentGate.app" --build-only
.venv/bin/python -m broker.mac_service --project-dir "$PWD" --config-dir "$HOME/.config/agentgate" --helper-path "$HOME/Applications/AgentGate.app/Contents/MacOS/AgentGateKeychain"
```

Stop the previous broker once, then open **AgentGate.app** and enter the original master password in its secure setup window. Save and Open validates the existing vault, saves the unlock, and loads the installed login service. Future app launches simply open the browser. Enable/Disable automatic startup and Forget saved unlock are available in the AgentGate application menu. Disabling stops the broker and preserves accounts; forgetting unlock does not stop an already-unlocked broker.

The vault must be a private owner-controlled regular file (`0600`) in a private configuration directory. New credential writes preserve that mode. Existing installations created by the earlier terminal broker may need a one-time permissions correction after stopping that broker; it does not require changing or decrypting the stored contents.

The native helper's private `read` command refuses to display a saved password when stdout is a terminal. The broker captures its output through a pipe. Use the setup app to manage the saved unlock.

Run `examples/background_smoke.py` with the virtualenv Python on macOS to verify actual launchd startup and supervised restart using temporary sample data. It never uses live provider accounts or stores a real password in its fake test helper.
